package netinfo

import (
	"net"
	"net/url"
	"testing"
)

func TestContainsNet(t *testing.T) {
	_, outer, _ := net.ParseCIDR("192.168.1.0/24")
	_, inner, _ := net.ParseCIDR("192.168.1.0/28")
	_, other, _ := net.ParseCIDR("10.0.0.0/24")
	if !ContainsNet(outer, inner) {
		t.Fatal("expected /24 to contain /28")
	}
	if ContainsNet(inner, outer) {
		t.Fatal("expected /28 not to contain /24")
	}
	if ContainsNet(outer, other) {
		t.Fatal("expected different nets not contained")
	}
}

func TestRangeAllowed(t *testing.T) {
	_, local, _ := net.ParseCIDR("192.168.1.0/24")
	_, targetOK, _ := net.ParseCIDR("192.168.1.0/28")
	_, targetBad, _ := net.ParseCIDR("10.0.0.0/24")

	if err := RangeAllowed([]*net.IPNet{targetOK}, []*net.IPNet{local}, false); err != nil {
		t.Fatalf("expected allowed: %v", err)
	}
	if err := RangeAllowed([]*net.IPNet{targetBad}, []*net.IPNet{local}, false); err == nil {
		t.Fatal("expected rejection for non-local CIDR")
	}
	if err := RangeAllowed([]*net.IPNet{targetBad}, []*net.IPNet{local}, true); err != nil {
		t.Fatalf("custom opt-in should allow: %v", err)
	}
}

func TestHostsInCIDR(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.1.0/30")
	hosts := HostsInCIDR(n, 256)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts for /30, got %d", len(hosts))
	}
}

func TestParseCIDRList(t *testing.T) {
	nets, err := ParseCIDRList("192.168.1.0/24, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d", len(nets))
	}
}

func TestURLOnHost(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"http://192.168.1.5:1400/xml/desc.xml", true},
		{"HTTPS://192.168.1.5/", true},
		{"http://192.168.1.6/", false},
		{"http://router.local/", false},
		{"http://192.168.1.5@10.0.0.1/", false},
		{"http://127.0.0.1:8080/", false},
		{"ftp://192.168.1.5/", false},
		{"/relative/path", false},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", c.raw, err)
		}
		if got := URLOnHost(u, "192.168.1.5"); got != c.want {
			t.Errorf("URLOnHost(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestUniqueHosts(t *testing.T) {
	parse := func(cidrs ...string) []*net.IPNet {
		var out []*net.IPNet
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return out
	}
	// A /24 inside a /23 adds nothing; the overlap is scanned once.
	hosts, ok := UniqueHosts(parse("192.168.0.0/23", "192.168.1.0/24"), 1024)
	if !ok || len(hosts) != 510 {
		t.Fatalf("overlap: ok=%v n=%d, want 510", ok, len(hosts))
	}
	// Two /23s fit exactly at 1,020; a /16 never does.
	if _, ok := UniqueHosts(parse("10.0.0.0/23", "10.0.2.0/23"), 1020); !ok {
		t.Fatal("expected 1,020 addresses to fit a limit of 1,020")
	}
	if _, ok := UniqueHosts(parse("10.0.0.0/23", "10.0.2.0/23"), 1019); ok {
		t.Fatal("expected 1,020 addresses to exceed a limit of 1,019")
	}
	if _, ok := UniqueHosts(parse("172.17.0.0/16"), 1024); ok {
		t.Fatal("expected a /16 to exceed the limit")
	}
}
