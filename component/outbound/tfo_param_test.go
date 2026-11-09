package outbound

import "testing"

func TestNodeRequestsTfo(t *testing.T) {
	cases := []struct {
		link string
		want bool
	}{
		{"vless://uuid@1.2.3.4:443?sni=a.example.com&tfo=1&type=tcp#n", true},
		{"trojan://pass@1.2.3.4:443?sni=a.example.com&tcp_fast_open=true#n", true},
		{"trojan://pass@1.2.3.4:443?sni=a.example.com&tfo=false#n", false},
		{"trojan://pass@1.2.3.4:443?sni=a.example.com#n", false},
		{"trojan://pass@1.2.3.4:443?sni=a.example.com&tfo=notabool#n", false},
		{"not a url at all %", false},
	}
	for _, c := range cases {
		if got := nodeRequestsTfo(c.link); got != c.want {
			t.Errorf("nodeRequestsTfo(%q) = %v, want %v", c.link, got, c.want)
		}
	}
}
