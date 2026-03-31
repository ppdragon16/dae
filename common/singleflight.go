// Revised from golang.org/x/sync/singleflight.

package common

import (
	"sync"
)

// call is an in-flight or completed singleflight.Do call
type call[V any] struct {
	wg sync.WaitGroup

	// These fields are written once before the WaitGroup is done
	// and are only read after the WaitGroup is done.
	val V
	err error

	// These fields are read and written with the singleflight
	// mutex held before the WaitGroup is done, and are read but
	// not written after the WaitGroup is done.
	dups int
}

// Group represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type SingleFlight[K comparable, V any, P any] struct {
	mu sync.Mutex     // protects m
	m  map[K]*call[V] // lazily initialized
}

// Result holds the results of Do, so they can be passed
// on a channel.
type Result struct {
	Val    interface{}
	Err    error
	Shared bool
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value shared indicates whether v was given to multiple callers.
func (g *SingleFlight[K, V, P]) Do(key K, param P, fn func(P) (V, error)) (v V, err error, leader bool, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[K]*call[V])
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.mu.Unlock()
		c.wg.Wait()

		return c.val, c.err, false, true
	}
	c := new(call[V])
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	g.doCall(c, key, param, fn)
	dups := c.dups
	return c.val, c.err, true, dups > 0
}

// doCall handles the single call for a key.
func (g *SingleFlight[K, V, P]) doCall(c *call[V], key K, param P, fn func(P) (V, error)) {
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()

	c.val, c.err = fn(param)
}
