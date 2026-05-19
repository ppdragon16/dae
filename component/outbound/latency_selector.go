package outbound

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

type LatencyBasedSelector struct {
	BaseSelector
	tolerance time.Duration

	dialerToAlive   map[*dialer.Dialer]bool
	dialerToLatency map[*dialer.Dialer]time.Duration

	networkIndexToDialer [4]*dialer.Dialer
	mu                   sync.RWMutex
}

func NewLatencyBasedSelector(dialerGroup *DialerGroup, tolerance time.Duration, aliveChangeCallback func(alive bool, networkType *common.NetworkType)) Selector {
	return &LatencyBasedSelector{
		BaseSelector: BaseSelector{
			dialerGroup:         dialerGroup,
			aliveChangeCallback: aliveChangeCallback,
		},
		tolerance:       tolerance,
		dialerToAlive:   make(map[*dialer.Dialer]bool),
		dialerToLatency: make(map[*dialer.Dialer]time.Duration),
	}
}

func (s *LatencyBasedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	index := common.NetworkTypeToIndex(networkType)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.networkIndexToDialer[index]
}

func (s *LatencyBasedSelector) getSortingLatency(d *dialer.Dialer) time.Duration {
	return s.dialerToLatency[d] + s.dialerGroup.dialerToAnnotation[d].AddLatency
}

var dialerSlicePool = sync.Pool{
	New: func() interface{} {
		return make([]*dialer.Dialer, 0, 10)
	},
}

func (s *LatencyBasedSelector) getSortedAliveDialers(networkType *common.NetworkType, buf []*dialer.Dialer) (aliveDialers []*dialer.Dialer) {
	allDialers := s.dialerGroup.Dialers
	aliveDialers = buf[:0]
	for _, d := range allDialers {
		if isDialerAlive(d, networkType) {
			aliveDialers = append(aliveDialers, d)
		}
	}

	slices.SortStableFunc(aliveDialers, func(dI, dJ *dialer.Dialer) int {
		latencyI, latencyJ := s.getSortingLatency(dI), s.getSortingLatency(dJ)
		priorityI, priorityJ := s.dialerGroup.GetPriority(dI, latencyI), s.dialerGroup.GetPriority(dJ, latencyJ)
		if priorityI == priorityJ {
			if latencyI < latencyJ {
				return -1
			}
			if latencyI > latencyJ {
				return 1
			}
			return 0
		}
		return priorityJ - priorityI
	})
	return aliveDialers
}

func isDialerAlive(dialer *dialer.Dialer, networkType *common.NetworkType) bool {
	if !dialer.Alive() {
		return false
	}
	if networkType != nil && !dialer.Supported(common.NetworkTypeToIndex(networkType)) {
		return false
	}
	return true
}

func (s *LatencyBasedSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dialersBuf := dialerSlicePool.Get().([]*dialer.Dialer)
	aliveDialers := s.getSortedAliveDialers(networkType, dialersBuf)
	s.printLatencies(aliveDialers, networkType, logfn)
	dialerSlicePool.Put(aliveDialers[:0])
}

// TODO: 由于tolerance 的存在, 第一个 aliveDialer 并不一定是当前选定的 dialer, 该方法需要修改
func (s *LatencyBasedSelector) printLatencies(aliveDialers []*dialer.Dialer, networkType *common.NetworkType, logfn func(args ...interface{})) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", s.dialerGroup.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", s.dialerGroup.Name))
	}

	if len(aliveDialers) == 0 {
		builder.WriteString("\t<Empty>\n")
	} else {
		for i, dialer := range aliveDialers {
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			latencyStr := common.LatencyString(s.dialerToLatency[dialer], s.dialerGroup.dialerToAnnotation[dialer].AddLatency)
			if !dialer.NeedAliveState() {
				latencyStr = fmt.Sprintf("Always Alive (%v)", latencyStr)
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v%s\n", i+1, tagStr, dialer.Name, latencyStr, fmt.Sprintf(" (priority: %d)", s.dialerGroup.GetPriority(dialer, s.getSortingLatency(dialer)))))
		}
	}
	logfn(strings.TrimSuffix(builder.String(), "\n"))
}

func (s *LatencyBasedSelector) getLatencyData(dialer *dialer.Dialer) (latency time.Duration, hasLatency bool) {
	switch s.dialerGroup.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		latency, hasLatency = dialer.Latencies10[s.dialerGroup].LastLatency()
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		latency, hasLatency = dialer.Latencies10[s.dialerGroup].AvgLatency()
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		latency = dialer.MovingAverage[s.dialerGroup]
		hasLatency = latency > 0
	}
	return
}

func (s *LatencyBasedSelector) updateDialerAliveState(dialer *dialer.Dialer, alive bool) {
	if s.dialerToAlive[dialer] == alive {
		return
	}
	if alive {
		log.WithFields(log.Fields{
			"dialer": dialer.Name,
			"group":  s.dialerGroup.Name,
		}).Warnf("[NOT ALIVE --> ALIVE]")
	} else {
		log.WithFields(log.Fields{
			"dialer": dialer.Name,
			"group":  s.dialerGroup.Name,
		}).Infof("[ALIVE --> NOT ALIVE]")
	}
	s.dialerToAlive[dialer] = alive
}

func (s *LatencyBasedSelector) logDialerSelection(oldBestDialer *dialer.Dialer, newBestDialer *dialer.Dialer, networkType *common.NetworkType) {
	var logLevel log.Level
	if oldBestDialer == nil {
		logLevel = log.WarnLevel
	} else {
		logLevel = log.InfoLevel
	}
	if !log.IsLevelEnabled(logLevel) {
		return
	}

	var re string
	var oldDialerName, newDialerName string

	if oldBestDialer == nil {
		oldDialerName = "<nil>"
	} else {
		re = "re-"
		oldDialerName = oldBestDialer.Name
	}

	if newBestDialer == nil {
		newDialerName = "<nil>"
	} else {
		newDialerName = newBestDialer.Name
	}

	logFields := log.Fields{
		"_new_dialer": newDialerName,
		"_old_dialer": oldDialerName,
		"group":       s.dialerGroup.Name,
		"network":     networkType.String(),
	}
	if newBestDialer != nil {
		logFields[string(s.dialerGroup.selectionPolicy.Policy)] = common.LatencyString(s.dialerToLatency[newBestDialer], s.dialerGroup.dialerToAnnotation[newBestDialer].AddLatency)
	}
	if oldBestDialer == nil {
		log.WithFields(logFields).Warnf("Group %vselects dialer", re)
	} else {
		log.WithFields(logFields).Infof("Group %vselects dialer", re)
	}
}

func (s *LatencyBasedSelector) logCheckLatency(aliveDialers []*dialer.Dialer, dialer *dialer.Dialer, networkType *common.NetworkType) {
	if !dialer.Supported(common.NetworkTypeToIndex(networkType)) {
		return
	}

	lastLatency, ok := dialer.Latencies10[s.dialerGroup].LastLatency()
	if !ok {
		return
	}
	labels := [...]string{s.dialerGroup.Name, dialer.Property.SubscriptionTag, dialer.Name, networkType.String()}
	common.Metrics.CheckLatency.With4(labels).Set(int64(lastLatency.Milliseconds()))

	movingLatency := dialer.MovingAverage[s.dialerGroup]
	if movingLatency > 0 {
		common.Metrics.CheckMovingLatency.With4(labels).Set(int64(movingLatency.Milliseconds()))
	}

	selectLatency := s.getSortingLatency(dialer)
	if selectLatency > 0 {
		common.Metrics.CheckSelectLatency.With4(labels).Set(int64(selectLatency.Milliseconds()))
	}

	found := false
	for i, d := range aliveDialers {
		if d == dialer {
			found = true
		}
		lab := [...]string{s.dialerGroup.Name, d.Property.SubscriptionTag, d.Name, networkType.String()}
		common.Metrics.DialerSelectIndex.With4(lab).Set(int64(i))
	}
	if !found {
		common.Metrics.DialerSelectIndex.With4(labels).Set(999)
	}
}

func (s *LatencyBasedSelector) NotifyStatusChange(d *dialer.Dialer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updateDialerAliveState(d, d.Alive())

	latency, hasLatency := s.getLatencyData(d)
	if hasLatency {
		s.dialerToLatency[d] = latency
	}
	var oncePrintLatencies sync.Once
	dialersBuf := dialerSlicePool.Get().([]*dialer.Dialer)
	defer func() {
		dialerSlicePool.Put(dialersBuf[:0])
	}()

	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		aliveDialers := s.getSortedAliveDialers(networkType, dialersBuf)
		dialersBuf = aliveDialers
		oldDialer := s.networkIndexToDialer[i]
		var newDialer *dialer.Dialer
		if len(aliveDialers) > 0 {
			newDialer = aliveDialers[0]
		}
		s.logCheckLatency(aliveDialers, d, networkType)
		if oldDialer != newDialer {
			switch {
			case oldDialer == nil,
				newDialer == nil,
				!s.dialerToAlive[oldDialer]:
				s.networkIndexToDialer[i] = newDialer
				s.logDialerSelection(oldDialer, newDialer, networkType)
				oncePrintLatencies.Do(func() {
					s.printLatencies(aliveDialers, networkType, log.Warnln)
				})
			default:
				oldLatency := s.getSortingLatency(oldDialer)
				newLatency := s.getSortingLatency(newDialer)
				oldPriority := s.dialerGroup.GetPriority(oldDialer, oldLatency)
				newPriority := s.dialerGroup.GetPriority(newDialer, newLatency)
				switch {
				case newPriority > oldPriority,
					newPriority == oldPriority && hasLatency && newLatency < oldLatency-s.tolerance:
					s.networkIndexToDialer[i] = newDialer
					s.logDialerSelection(oldDialer, newDialer, networkType)
					oncePrintLatencies.Do(func() {
						s.printLatencies(aliveDialers, networkType, log.Warnln)
					})
				}
			}
		}
		// oncePrintLatencies.Do(func() {
		// 	s.printLatencies(aliveDialers, networkType, log.Infoln)
		// })
		s.handleAliveStateChange(newDialer != nil, networkType)
	}
}
