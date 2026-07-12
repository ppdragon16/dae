/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package fastlog provides a zero-allocation logger for high-frequency
// Info-level events (DNS requests, TCP/UDP connections). It bypasses
// logrus entirely and writes directly to the output using pooled buffers
// and append-based formatting.
package fastlog

import (
	"io"
	"sync"
	"time"
)

// Logger is a zero-allocation structured logger for high-frequency events.
// All methods are safe for concurrent use.
type Logger struct {
	mu  sync.Mutex // serializes writes to out
	out io.Writer

	tsMu   sync.RWMutex
	tsUnix int64  // unix second of cached timestamp
	tsBuf  []byte // pre-formatted timestamp bytes
}

var std *Logger

// Configure initializes the global fast-log singleton.
// It should be called once during startup from SetLogger.
func Configure(out io.Writer) {
	std = &Logger{out: out}
}

// Enabled reports whether the fast logger has been configured.
func Enabled() bool {
	return std != nil
}

// getTs returns a cached timestamp as []byte.
// time.Time.Format is called at most once per second.
func (l *Logger) getTs() []byte {
	now := time.Now()
	unix := now.Unix()

	l.tsMu.RLock()
	if l.tsUnix == unix && len(l.tsBuf) > 0 {
		b := l.tsBuf
		l.tsMu.RUnlock()
		return b
	}
	l.tsMu.RUnlock()

	l.tsMu.Lock()
	defer l.tsMu.Unlock()
	// Double-check after acquiring write lock.
	if l.tsUnix == unix && len(l.tsBuf) > 0 {
		return l.tsBuf
	}
	s := now.Format("Jan 02 15:04:05")
	l.tsBuf = []byte(s)
	l.tsUnix = unix
	return l.tsBuf
}

// writeBuf writes the buffer to the output. It acquires the write lock
// for serialization and releases it immediately after Write returns.
func (l *Logger) writeBuf(buf []byte) {
	l.mu.Lock()
	l.out.Write(buf)
	l.mu.Unlock()
}
