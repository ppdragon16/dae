package cmd

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

// TestValidateFixedDomainTtlRejectsBadTtl pins the invariant that
// `dae validate` exits non-zero on a fixed_domain_ttl entry the daemon would
// reject at start: the TTL parser runs in ControlPlane construction, not in
// config loading, so validate must dry-run it explicitly.
func TestValidateFixedDomainTtlRejectsBadTtl(t *testing.T) {
	conf := &config.Config{}
	conf.Dns = config.Dns{
		FixedDomainTtl: []config.KeyableString{`"example.com: not-a-number"`},
	}
	err := validateFixedDomainTtl(conf)
	if err == nil {
		t.Fatal("expected an error for a non-numeric ttl")
	}
	// The error must name the broken entry, not just the parser failure.
	if !strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error does not name the offending entry: %v", err)
	}
}

// TestValidateFixedDomainTtlAcceptsGoodTtl keeps the gate from over-firing on
// the documented entry shape (whole "name: ttl" quoted, with padding).
func TestValidateFixedDomainTtlAcceptsGoodTtl(t *testing.T) {
	conf := &config.Config{}
	conf.Dns = config.Dns{
		// The config parser delivers the quoted entry as an unquoted
		// KeyableString literal, which is the shape ParseFixedDomainTtl
		// actually sees at start.
		FixedDomainTtl: []config.KeyableString{`example.com: 300`, `a.b.c : 0x10`},
	}
	if err := validateFixedDomainTtl(conf); err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}

	// The control-plane parser and the validate dry-run are the same call, so
	// the "validate passes => daemon starts" invariant holds by construction.
	if _, err := control.ParseFixedDomainTtl(conf.Dns.FixedDomainTtl); err != nil {
		t.Fatalf("control.ParseFixedDomainTtl diverged from the validate dry-run: %v", err)
	}
}
