/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"testing"
	"time"
)

func TestTimeWheelCacheClear(t *testing.T) {
	c := NewTimeWheelCache[int, string](time.Hour, time.Second, nil)
	defer c.Close()

	c.Save(1, "one")
	c.Save(2, "two")
	if _, ok := c.Get(1); !ok {
		t.Fatal("entry 1 should exist before clear")
	}

	c.Clear()
	if _, ok := c.Get(1); ok {
		t.Fatal("entry 1 should be gone after clear")
	}
	if _, ok := c.Get(2); ok {
		t.Fatal("entry 2 should be gone after clear")
	}
}
