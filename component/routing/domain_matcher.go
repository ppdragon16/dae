/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import "github.com/daeuniverse/dae/common/consts"

type DomainMatcher interface {
	AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey)
	Build() error
	MatchDomainBitmap(domain string) (bitmap []uint32)
	MatchDomainBitmapInplace(domain string, bitmap []uint32)
	// Release frees shared interned matcher structures referenced by this
	// matcher. Call it when the matcher is discarded (e.g. on hot-swap).
	Release()
}
