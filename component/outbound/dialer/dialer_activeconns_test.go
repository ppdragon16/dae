/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"net"
	"sync"
	"testing"
	"time"
)

// newRegistryTestDialer builds a Dialer suitable for activeConns registry
// tests. The alive-state machinery is inert here: RegisterConn,
// UnregisterConn and AbortConns only touch activeConns under activeConnsMu.
func newRegistryTestDialer() *Dialer {
	return NewDialer(&mockNetDialer{}, &GlobalOption{}, &Property{}, false)
}

func TestRegisterUnregisterConn(t *testing.T) {
	d := newRegistryTestDialer()
	lConn, rConn := net.Pipe()
	defer lConn.Close()
	defer rConn.Close()

	d.RegisterConn(lConn, rConn)
	if got := d.activeConns[rConn]; got != net.Conn(lConn) {
		t.Fatalf("activeConns[rConn] = %v, want the registered lConn", got)
	}

	d.UnregisterConn(rConn)
	if len(d.activeConns) != 0 {
		t.Fatalf("len(activeConns) = %d, want 0 after UnregisterConn", len(d.activeConns))
	}
}

func TestAbortConnsClosesBothEnds(t *testing.T) {
	d := newRegistryTestDialer()
	var pairs [][2]net.Conn
	for i := 0; i < 2; i++ {
		l, r := net.Pipe()
		pairs = append(pairs, [2]net.Conn{l, r})
		d.RegisterConn(l, r)
	}

	d.AbortConns()
	if len(d.activeConns) != 0 {
		t.Fatalf("len(activeConns) = %d, want 0 after AbortConns", len(d.activeConns))
	}
	for i, p := range pairs {
		for j, c := range p {
			if err := c.SetDeadline(time.Now()); err == nil {
				t.Fatalf("pairs[%d][%d] still usable after AbortConns: it was never closed", i, j)
			}
		}
	}
}

// closeOrderConn records Close() calls so tests can assert the documented
// "close lConn before rConn" ordering contract of AbortConns.
type closeOrderConn struct {
	net.Conn
	name  string
	mu    *sync.Mutex
	order *[]string
}

func (c *closeOrderConn) Close() error {
	c.mu.Lock()
	*c.order = append(*c.order, c.name)
	c.mu.Unlock()
	return c.Conn.Close()
}

func TestAbortConnsClosesLocalSideFirst(t *testing.T) {
	d := newRegistryTestDialer()
	var mu sync.Mutex
	var order []string
	l, r := net.Pipe()
	lw := &closeOrderConn{Conn: l, name: "lConn", mu: &mu, order: &order}
	rw := &closeOrderConn{Conn: r, name: "rConn", mu: &mu, order: &order}

	d.RegisterConn(lw, rw)
	d.AbortConns()
	if len(order) != 2 || order[0] != "lConn" || order[1] != "rConn" {
		t.Fatalf("close order = %v, want [lConn rConn]", order)
	}
}

func TestActiveConnsConcurrentAccess(t *testing.T) {
	d := newRegistryTestDialer()
	const workers, iters = 8, 500
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				l, r := net.Pipe()
				d.RegisterConn(l, r)
				d.UnregisterConn(r)
				_ = l.Close()
				_ = r.Close()
			}
		}()
	}
	wg.Wait()
	if len(d.activeConns) != 0 {
		t.Fatalf("len(activeConns) = %d, want 0 after all workers done", len(d.activeConns))
	}
	d.AbortConns() // must be a safe no-op on an empty registry
}
