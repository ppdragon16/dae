/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// TestDatapathEventLayout pins the wire format shared with kern/tproxy.c. The C
// side asserts sizeof(struct dae_event) == 24 at compile time; a mismatch here
// would silently misdecode every event.
func TestDatapathEventLayout(t *testing.T) {
	if got := unsafe.Sizeof(datapathEvent{}); got != 24 {
		t.Fatalf("datapathEvent size = %d, want 24 (mirror kern/tproxy.c)", got)
	}
	raw := make([]byte, 24)
	errno := int32(-7) // E2BIG: the map was full
	binary.NativeEndian.PutUint64(raw[0:8], 1234567890)
	binary.NativeEndian.PutUint32(raw[8:12], datapathEventRoutingTuplesWriteFailed)
	binary.NativeEndian.PutUint32(raw[12:16], routingTuplesSiteUdpNewFlow)
	binary.NativeEndian.PutUint32(raw[16:20], uint32(errno))
	binary.NativeEndian.PutUint32(raw[20:24], 17)

	ev, err := decodeDatapathEvent(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if ev.TimestampNs != 1234567890 || ev.Type != datapathEventRoutingTuplesWriteFailed ||
		ev.Site != routingTuplesSiteUdpNewFlow || ev.Errno != -7 || ev.L4Proto != 17 {
		t.Fatalf("decoded event mismatch: %+v", ev)
	}
	if _, err := decodeDatapathEvent(raw[:23]); err == nil {
		t.Fatal("a short sample must be rejected")
	}
}

// TestDatapathEventSlotLayout pins sizeof(struct dae_event_slot).
func TestDatapathEventSlotLayout(t *testing.T) {
	if got := unsafe.Sizeof(datapathEventSlot{}); got != datapathEventSlotSize {
		t.Fatalf("datapathEventSlot size = %d, want %d", got, datapathEventSlotSize)
	}
}

// TestDatapathSlotKey mirrors EVENT_SLOT_KEY in kern/tproxy.c: the reader and
// the writer must agree on which slot a (type, site) pair lives in.
func TestDatapathSlotKey(t *testing.T) {
	cases := []struct {
		eventType, site, want uint32
	}{
		{datapathEventRoutingTuplesWriteFailed, routingTuplesSiteUdpNewFlow, 8 + 1},
		{datapathEventRoutingTuplesWriteFailed, routingTuplesSiteTcpDirect, 8 + 2},
		{datapathEventRedirectTrackWriteFailed, 0, 16},
		{datapathEventCookiePidWriteFailed, 2, 24 + 2},
		// Out-of-range values must wrap exactly like EVENT_SLOT_KEY does, so a
		// future event type cannot silently alias another slot.
		{datapathEventSlotTypes, 0, 0},
		{1, datapathEventSlotSites, 8},
	}
	for _, c := range cases {
		if got := datapathSlotKey(c.eventType, c.site); got != c.want {
			t.Fatalf("slot key(%d,%d) = %d, want %d", c.eventType, c.site, got, c.want)
		}
	}
}

func TestEventSlotDelta(t *testing.T) {
	cases := []struct {
		previous, current, want uint64
	}{
		{0, 0, 0}, // quiet map stays quiet
		{0, 5, 5}, // no baseline yet: report the whole count once
		{5, 5, 0}, // unchanged
		{5, 9, 4}, // growth
		{9, 4, 0}, // counters never go backwards; treat as no news
	}
	for _, c := range cases {
		if got := eventSlotDelta(c.previous, c.current); got != c.want {
			t.Fatalf("eventSlotDelta(%d,%d) = %d, want %d", c.previous, c.current, got, c.want)
		}
	}
}

// TestDatapathEventSinkWakesJanitorOnPressure pins the reaction that matters:
// a rejected routing-tuple write must ask for an immediate sweep, while a
// process-name mapping failure must not (the janitor cannot free those
// quickly and the routing itself is unaffected).
func TestDatapathEventSinkWakesJanitorOnPressure(t *testing.T) {
	var janitor bpfMapJanitor
	sink := &datapathEventSink{janitor: &janitor}

	sink.HandleDatapathEvent(datapathEvent{
		Type:  datapathEventRoutingTuplesWriteFailed,
		Site:  routingTuplesSiteUdpNewFlow,
		Errno: -7,
	})
	if !janitor.pressure.Load() {
		t.Fatal("a routing_tuples write failure must request an immediate sweep")
	}
	if !janitor.pressure.Swap(false) {
		t.Fatal("pressure flag must be set exactly once per request")
	}
	if janitor.pressure.Load() {
		t.Fatal("reading the pressure flag must clear it")
	}

	sink.HandleDatapathEvent(datapathEvent{Type: datapathEventCookiePidWriteFailed})
	if janitor.pressure.Load() {
		t.Fatal("a cookie_pid failure must not request a sweep")
	}

	sink.HandleDatapathEvent(datapathEvent{Type: datapathEventRedirectTrackWriteFailed})
	if !janitor.pressure.Load() {
		t.Fatal("a redirect_track write failure must request an immediate sweep")
	}
}
