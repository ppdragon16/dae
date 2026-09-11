/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	AnnotationKey_AddLatency  = "add_latency"
	AnnotationKey_Priority    = "priority"
	AnnotationKey_DnsCacheTag = "dns_cache_tag"
	AnnotationKey_Ecs         = "ecs"

	// EcsModeStrip removes any EDNS0 Client Subnet option from queries
	// forwarded via the annotated dialer.
	EcsModeStrip = "strip"

	// EcsModePass forwards the client's EDNS0 Client Subnet option
	// as-is, overriding a strip global default for this dialer.
	EcsModePass = "pass"
)

type Priority struct {
	Pri  int
	Low  time.Duration
	High time.Duration
}

// EcsSpec is the resolved EDNS0 Client Subnet policy of a dialer.
// Strip and Prefix are mutually exclusive; a nil *EcsSpec on the
// annotation means pass-through (forward the client's ECS as-is).
type EcsSpec struct {
	// Strip removes the ECS option from forwarded queries.
	Strip bool
	// PassThrough forwards the client's ECS option as-is. It exists to
	// override a strip global default at dialer granularity; a nil
	// *EcsSpec on the annotation already means "no annotation policy".
	PassThrough bool
	// Prefix, when Strip and PassThrough are false, is the subnet
	// injected into (or replacing the client's) ECS option. Host bits
	// are masked off.
	Prefix netip.Prefix
	// Key is the canonical identity used for DNS cache key mixing
	// ("strip", "pass", or the masked prefix in string form).
	Key string
}

type Annotation struct {
	AddLatency time.Duration
	Priority   int
	// Optional conditional priorities based on latency range.
	ConditionalPriority []*Priority
	// DnsCacheTag groups dialers sharing the same DNS cache.
	// Dialers with the same non-empty tag share DNS cache entries,
	// while dialers with different tags are isolated.
	// When empty, falls back to per-group caching (default behavior).
	DnsCacheTag string
	// Ecs carries the per-dialer EDNS0 Client Subnet policy
	// ("strip" or a CIDR prefix). Nil means pass-through.
	Ecs *EcsSpec
}

func (p *Priority) String() string {
	return fmt.Sprintf("(%d,%v,%v)", p.Pri, p.Low, p.High)
}

func ParsePriority(priorityStr string) (pri int, condPris []*Priority, err error) {
	// <default priority>; <priority>(<latency_low>,<latency_high>); <more...>
	reDefault := regexp.MustCompile(`^\s*(\d+)\s*`)
	defaultMatch := reDefault.FindStringSubmatch(priorityStr)
	if len(defaultMatch) == 0 {
		return 0, nil, fmt.Errorf("bad priority format")
	}
	priority, err := strconv.Atoi(defaultMatch[1])
	if err != nil {
		return 0, nil, fmt.Errorf("incorrect priority number: %w", err)
	}
	pri = priority
	reConditional := regexp.MustCompile(`(\d+)\(([^,]*),([^,]*)\)`)
	conditionalMatches := reConditional.FindAllStringSubmatch(priorityStr, -1)
	for _, conditionalMatch := range conditionalMatches {
		pri, err := strconv.Atoi(conditionalMatch[1])
		if err != nil {
			return 0, nil, fmt.Errorf("incorrect priority number: %w", err)
		}
		lowStr := strings.TrimSpace(conditionalMatch[2])
		highStr := strings.TrimSpace(conditionalMatch[3])
		low := time.Duration(0)
		if lowStr != "" {
			low, err = time.ParseDuration(lowStr)
			if err != nil {
				return 0, nil, fmt.Errorf("incorrect priority low: %w", err)
			}
		}

		high := time.Duration(math.MaxInt64)
		if highStr != "" {
			high, err = time.ParseDuration(highStr)
			if err != nil {
				return 0, nil, fmt.Errorf("incorrect priority high: %w", err)
			}
		}
		condPris = append(condPris, &Priority{
			Pri:  pri,
			Low:  low,
			High: high,
		})
	}
	return pri, condPris, nil
}

// ParseEcs validates and canonicalizes the value of the "ecs" annotation:
// "strip", "pass", or a CIDR prefix (e.g. "203.0.113.0/24") whose host
// bits are masked off. An empty value means "no annotation policy" (the
// global dns.ecs default applies).
func ParseEcs(val string) (*EcsSpec, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil, nil
	}
	switch val {
	case EcsModeStrip:
		return &EcsSpec{Strip: true, Key: EcsModeStrip}, nil
	case EcsModePass:
		return &EcsSpec{PassThrough: true, Key: EcsModePass}, nil
	}
	prefix, err := netip.ParsePrefix(val)
	if err != nil {
		return nil, fmt.Errorf("incorrect ecs format (want 'strip' or CIDR like '203.0.113.0/24'): %w", err)
	}
	prefix = prefix.Masked()
	return &EcsSpec{Prefix: prefix, Key: prefix.String()}, nil
}

func NewAnnotation(annotation []*config_parser.Param) (*Annotation, error) {
	var anno Annotation
	for _, param := range annotation {
		switch param.Key {
		case AnnotationKey_AddLatency:
			latency, err := time.ParseDuration(param.Val)
			if err != nil {
				return nil, fmt.Errorf("incorrect latency format: %w", err)
			}
			anno.AddLatency = latency
		case AnnotationKey_Priority:
			pri, condPris, err := ParsePriority(param.Val)
			if err != nil {
				return nil, fmt.Errorf("incorrect priority format: %w", err)
			}
			anno.Priority = pri
			anno.ConditionalPriority = condPris
		case AnnotationKey_DnsCacheTag:
			anno.DnsCacheTag = param.Val
		case AnnotationKey_Ecs:
			ecs, err := ParseEcs(param.Val)
			if err != nil {
				return nil, err
			}
			anno.Ecs = ecs
		default:
			return nil, fmt.Errorf("unknown filter annotation: %v", param.Key)
		}
	}
	return &anno, nil
}
