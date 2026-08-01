/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

var ErrNoDialer = fmt.Errorf("no dialer")
var ErrNoAliveDialer = fmt.Errorf("no alive dialer")

type DialerGroup struct {
	Name            string
	Dialers         []*dialer.Dialer
	selectionPolicy *dialer.DialerSelectionPolicy
	selector        Selector

	dialerToAnnotation map[*dialer.Dialer]*dialer.Annotation

	mu sync.RWMutex
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *common.NetworkType),
) *DialerGroup {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}

	g := &DialerGroup{
		Name:               name,
		Dialers:            dialers,
		selectionPolicy:    &selectionPolicy,
		dialerToAnnotation: make(map[*dialer.Dialer]*dialer.Annotation),
	}

	for i, d := range dialers {
		g.dialerToAnnotation[d] = dialersAnnotations[i]
	}

	switch selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_MinLastLatency:
		g.selector = NewLatencyBasedSelector(g, option.CheckTolerance, aliveChangeCallback)
	case consts.DialerSelectionPolicy_Fixed:
		g.selector = NewFixedSelector(g, aliveChangeCallback)
	case consts.DialerSelectionPolicy_Random:
		g.selector = NewRandomSelector(g, aliveChangeCallback)
	}

	for _, d := range dialers {
		d.RegisterDialerGroup(g)
		g.NotifyStatusChange(d)
	}

	return g
}

func (g *DialerGroup) Close() error {
	for _, d := range g.Dialers {
		d.UnregisterDialerGroup(g)
	}
	return nil
}

// ReplaceDialers atomically replaces the dialer set in this group.
// Dialers are matched by Property: old dialers whose Property matches a new
// dialer are recycled; the rest are unregistered. New dialers with no Property
// match are registered in their place.
func (g *DialerGroup) ReplaceDialers(
	newDialers []*dialer.Dialer,
	newAnnotations []*dialer.Annotation,
) {
	if len(newDialers) != len(newAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(newDialers), len(newAnnotations)))
	}

	g.mu.Lock()

	// Build lookup: old Property -> old Dialer (for recycling).
	oldByProperty := make(map[dialer.Property]*dialer.Dialer, len(g.Dialers))
	for _, d := range g.Dialers {
		oldByProperty[*d.Property] = d
	}

	// Build final dialer list: recycle old dialers where Property matches.
	finalDialers := make([]*dialer.Dialer, 0, len(newDialers))
	finalAnnos := make([]*dialer.Annotation, 0, len(newDialers))
	oldKept := make(map[*dialer.Dialer]bool, len(g.Dialers))

	for j, newD := range newDialers {
		if oldD, ok := oldByProperty[*newD.Property]; ok {
			// If the recycled dialer is currently marked not-alive, its
			// Latencies10 / MovingAverage are likely polluted with
			// TimeoutPenalty samples from the previous down period. Drop
			// them so the recovered node starts with a clean history on
			// this side of the update-sub.
			if !oldD.Alive() {
				oldD.ResetLatency()
			}
			finalDialers = append(finalDialers, oldD)
			finalAnnos = append(finalAnnos, newAnnotations[j])
			oldKept[oldD] = true
		} else {
			finalDialers = append(finalDialers, newD)
			finalAnnos = append(finalAnnos, newAnnotations[j])
		}
	}

	// Unregister old dialers that are leaving.
	for _, d := range g.Dialers {
		if !oldKept[d] {
			d.UnregisterDialerGroup(g)
		}
	}

	// Register new dialers (not recycled).
	for _, newD := range newDialers {
		if _, ok := oldByProperty[*newD.Property]; !ok {
			newD.RegisterDialerGroup(g)
		}
	}

	// Update state.
	g.Dialers = finalDialers
	g.dialerToAnnotation = make(map[*dialer.Dialer]*dialer.Annotation, len(finalDialers))
	for i, d := range finalDialers {
		g.dialerToAnnotation[d] = finalAnnos[i]
	}

	g.mu.Unlock()

	// Seed selector with current dialer state.
	for _, d := range finalDialers {
		g.NotifyStatusChange(d)
	}
}

func (g *DialerGroup) GetAnnotation(d *dialer.Dialer) *dialer.Annotation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.dialerToAnnotation[d]
}

// Returns the priority given an observed latency.
// If a "ConditionalPriority" is present, it is applied;
// Otherwise the default fixed Priority is returned.
func (g *DialerGroup) GetPriority(d *dialer.Dialer, latency time.Duration) int {
	g.mu.RLock()
	anno := g.dialerToAnnotation[d]
	g.mu.RUnlock()
	for _, p := range anno.ConditionalPriority {
		if latency >= p.Low && latency <= p.High {
			return p.Pri
		}
	}
	return anno.Priority
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.selectionPolicy.Policy
}

// SelectFallbackIpVersion selects a dialer from group according to selectionPolicy. If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) SelectFallbackIpVersion(networkType *common.NetworkType, strictIpVersion bool) (dialer *dialer.Dialer, fallback bool, err error) {
	dialer, err = g.Select(networkType)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		dialer, err = g.Select(networkType.GetAnotherIpVersion())
		fallback = true
	}
	return
}

func (g *DialerGroup) Select(networkType *common.NetworkType) (dialer *dialer.Dialer, err error) {
	g.mu.RLock()
	if len(g.Dialers) == 0 {
		g.mu.RUnlock()
		return nil, ErrNoDialer
	}
	g.mu.RUnlock()

select_dialer:
	dialer = g.selector.Select(networkType)
	if dialer == nil {
		return nil, ErrNoAliveDialer
	}

	if !dialer.Alive() {
		dialer.ReportUnavailable()
		goto select_dialer
	}

	return dialer, nil
}

func (g *DialerGroup) PrintLatency() {
	if log.IsLevelEnabled(log.InfoLevel) {
		for i := 0; i < 4; i++ {
			networkType := common.IndexToNetworkType(i)
			g.mu.RLock()
			g.selector.PrintLatencies(networkType, log.Infoln)
			g.mu.RUnlock()
		}
	}
}

func (g *DialerGroup) NotifyStatusChange(dialer *dialer.Dialer) {
	g.selector.NotifyStatusChange(dialer)
}

func (g *DialerGroup) GetEmaAlpha() float64 {
	return g.selectionPolicy.EmaAlpha
}

func (g *DialerGroup) GetTimeoutPenalty() time.Duration {
	return g.selectionPolicy.TimeoutPenalty
}
