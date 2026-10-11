package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/logger/fastlog"
	log "github.com/sirupsen/logrus"
)

// sniffTimeoutCause classifies what a sniffing timeout saw, and reports the TLS
// record's declared length and how much of it had arrived. It is the single
// source of truth for both the fastlog line and the logrus fallback.
//
// The mapping is exact, not heuristic: SniffTls only reports "need more" after
// it has seen a handshake record header whose declared length exceeds what
// arrived, and SniffHttp only after a valid method prefix, which requires a
// printable first byte. Any other shape returns a terminal verdict and never
// reaches the timeout path at all.
func sniffTimeoutCause(bytesRead int, head []byte) (cause fastlog.SniffTimeoutCause, recordLen, recordGot int) {
	switch {
	case bytesRead == 0 || len(head) == 0:
		return fastlog.SniffTimeoutNoFirstByte, 0, 0
	case head[0] == sniffing.ContentType_HandShake:
		if len(head) >= 5 {
			// record_got counts the bytes past the record header, so
			// record_len - record_got is what the deadline cut off.
			return fastlog.SniffTimeoutPartialTLS, int(binary.BigEndian.Uint16(head[3:5])), bytesRead - 5
		}
		return fastlog.SniffTimeoutPartialTLS, 0, bytesRead
	default:
		return fastlog.SniffTimeoutPartialHTTP, 0, 0
	}
}

// reportSniffTimeout emits the timeout line through fastlog when it is
// configured -- the zero-allocation path the dial log uses, which matters on a
// per-connection event -- and through logrus fields otherwise, so the line does
// not disappear where fastlog is off.
func reportSniffTimeout(src, dst netip.AddrPort, bytesRead int, head []byte, elapsed time.Duration) {
	cause, recordLen, recordGot := sniffTimeoutCause(bytesRead, head)
	if fastlog.Enabled() {
		fastlog.LogSniffTimeout(src, dst, cause, bytesRead, recordLen, recordGot, head, elapsed)
		return
	}
	log.WithFields(sniffTimeoutFields(src, dst, cause, bytesRead, recordLen, recordGot, head, elapsed)).Infoln("Sniffing timeout")
}

// sniffTimeoutFields builds the logrus fallback for the shapes above.
func sniffTimeoutFields(
	src, dst netip.AddrPort,
	cause fastlog.SniffTimeoutCause,
	bytesRead, recordLen, recordGot int,
	head []byte,
	elapsed time.Duration,
) log.Fields {
	fields := log.Fields{
		"src":     src.String(),
		"dst":     dst.String(),
		"bytes":   bytesRead,
		"elapsed": elapsed.Round(time.Millisecond).String(),
		"cause":   cause.String(),
	}
	if cause == fastlog.SniffTimeoutPartialTLS {
		fields["record_len"] = recordLen
		fields["record_got"] = recordGot
	}
	if len(head) > 0 {
		fields["head"] = fmt.Sprintf("% x", head)
	}
	return fields
}

// sniffAbortFields describes a sniff that ended on a non-timeout network error
// (a reset or a socket closed under it). bytes/head say whether the peer had
// sent anything before it went away, which is the difference between "it never
// spoke" and "it died mid-handshake".
func sniffAbortFields(src, dst netip.AddrPort, bytesRead int, head []byte, elapsed time.Duration) log.Fields {
	fields := log.Fields{
		"src":     src.String(),
		"dst":     dst.String(),
		"bytes":   bytesRead,
		"elapsed": elapsed.Round(time.Millisecond).String(),
	}
	if len(head) > 0 {
		fields["head"] = fmt.Sprintf("% x", head)
	}
	return fields
}

// reportSniffAbort reports the abort at debug: it is as common as the EOF case
// the caller filters out above (a browser's redundant happy-eyeballs
// connection, a probe that resets), so it must not add an Info line per event,
// but it must not be silent either -- "the peer went away mid-sniff" used to be
// indistinguishable from a sniffing failure.
//
// The caller checks the level before sampling SniffProgress, so a disabled
// debug level costs nothing on this path.
func reportSniffAbort(src, dst netip.AddrPort, err error, bytesRead int, head []byte, elapsed time.Duration) {
	log.WithError(err).
		WithFields(sniffAbortFields(src, dst, bytesRead, head, elapsed)).
		Debugln("Sniffing aborted")
}
