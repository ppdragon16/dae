/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/stretchr/testify/require"
)

// Should run successfully in less than 3.2 seconds.
func TestUdpTaskPool(t *testing.T) {
	c, err := cpu.Times(false)
	require.NoError(t, err)
	t.Log(c)
	DefaultNatTimeoutUDP = 1000 * time.Millisecond

	pool := NewUdpTaskPool[AddrPortPair, struct{}](AddrPortPairHash)

	key1 := AddrPortPair{Src: netip.MustParseAddrPort("1.1.1.1:1")}
	key2 := AddrPortPair{Src: netip.MustParseAddrPort("1.1.1.1:2")}
	key3 := AddrPortPair{Src: netip.MustParseAddrPort("1.1.1.1:3")}

	// Test task execution
	for i := 0; i <= UdpTaskQueueLength; i++ {
		pool.EmitTask(key1, &UdpTask[struct{}]{exec: func(_ *UdpTask[struct{}]) { time.Sleep(500 * time.Millisecond) }})
	} // Fill the queue to full
	time.Sleep(400 * time.Millisecond) // Task should be executed
	pool.EmitTask(key1, &UdpTask[struct{}]{exec: func(_ *UdpTask[struct{}]) {}})

	// Test task timeout
	for i := 0; i <= UdpTaskQueueLength; i++ {
		pool.EmitTask(key2, &UdpTask[struct{}]{exec: func(_ *UdpTask[struct{}]) { time.Sleep(500 * time.Millisecond) }})
	} // Fill the queue to full
	time.Sleep(200 * time.Millisecond) // Task should be executed
	pool.EmitTask(key2, &UdpTask[struct{}]{exec: func(_ *UdpTask[struct{}]) {}})

	// Test task gc with pending emit
	for i := 0; i <= UdpTaskQueueLength; i++ {
		pool.EmitTask(key3, &UdpTask[struct{}]{exec: func(_ *UdpTask[struct{}]) { time.Sleep(100 * time.Second) }})
	} // Fill the queue
	pool.EmitTask(key3, &UdpTask[struct{}]{exec: func(_ *UdpTask[struct{}]) {}})

	c, err = cpu.Times(false)
	require.NoError(t, err)
	t.Log(c)
}
