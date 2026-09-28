package outbound

import (
	"testing"

	D "github.com/daeuniverse/outbound/dialer"
)

// TestMasqueLinkRegistrable guards against the masque dialer silently
// disappearing from the registration list: the subscription parser only knows
// schemes whose dialer packages are imported here (component/outbound), and a
// missing import surfaces as "unexpected link type: masque" at subscription
// load time.
func TestMasqueLinkRegistrable(t *testing.T) {
	const link = "masque://[2404:c140:2202:0:f8e6:1aff:fe9f:8000]:7443?sni=hy2.test&insecure=1&zero_rtt=1#masque-vps"
	d, prop, err := D.NewFromLink(link)
	if err != nil {
		t.Fatalf("NewFromLink(%q): %v", link, err)
	}
	if prop == nil || prop.Protocol != "masque" {
		t.Fatalf("property = %+v, want protocol masque", prop)
	}
	if d == nil {
		t.Fatal("nil dialer")
	}
}
