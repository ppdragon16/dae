/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
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
)

type Priority struct {
	Pri  int
	Low  time.Duration
	High time.Duration
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
		default:
			return nil, fmt.Errorf("unknown filter annotation: %v", param.Key)
		}
	}
	return &anno, nil
}
