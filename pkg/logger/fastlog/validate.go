/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package fastlog

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"unicode/utf8"
)

// byteValidator wraps a log output and rejects non-UTF-8 writes. The dae log
// is UTF-8 text; a write of binary data (e.g. a DNS packet routed to the log
// file by an fd mix-up) silently corrupts it — line-oriented tooling and
// viewers choke on the invalid bytes, and concurrent log lines get torn.
// When such a write is detected it is dropped, and the hexdump plus the
// writing goroutine's stack go to stderr (i.e. procd's syslog, not the log
// file) so the culprit can be identified.
type ByteValidator struct {
	W io.Writer
}

func (v *ByteValidator) Write(p []byte) (int, error) {
	if !utf8.Valid(p) {
		const dumpLen = 128
		dump := p
		if len(dump) > dumpLen {
			dump = dump[:dumpLen]
		}
		fmt.Fprintf(os.Stderr,
			"dae: rejected non-utf8 write of %d bytes to the log; first %d bytes:\n%s\ngoroutine stack:\n%s\n",
			len(p), len(dump), hex.Dump(dump), debug.Stack())
		// Pretend success: logging must keep working for the goroutine that
		// (probably unknowingly) wrote here.
		return len(p), nil
	}
	return v.W.Write(p)
}
