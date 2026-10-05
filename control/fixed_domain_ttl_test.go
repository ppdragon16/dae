package control

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

// TestParseFixedDomainTtlRange pins the parse-time range check: a fixed TTL
// becomes a cache deadline via time.Duration(ttl) * time.Second, so zero and
// negative values expire immediately and values beyond MaxInt32 seconds
// overflow the Duration to a deadline in the past -- both must be rejected
// instead of silently un-caching the pinned domain. (Port of kdae 21aad88a.)
func TestParseFixedDomainTtlRange(t *testing.T) {
	if _, err := ParseFixedDomainTtl([]config.KeyableString{"example.com: 3600"}); err != nil {
		t.Fatalf("valid ttl rejected: %v", err)
	}
	for _, bad := range []string{"example.com: 0", "example.com: -5", "example.com: 2147483648"} {
		_, err := ParseFixedDomainTtl([]config.KeyableString{config.KeyableString(bad)})
		if err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
		if !strings.Contains(err.Error(), "must be 1..2147483647 seconds") {
			t.Fatalf("%q: unexpected error %v", bad, err)
		}
	}
	// The MaxInt32 boundary itself is accepted.
	if _, err := ParseFixedDomainTtl([]config.KeyableString{"example.com: 2147483647"}); err != nil {
		t.Fatalf("MaxInt32 seconds must be accepted, got %v", err)
	}
}
