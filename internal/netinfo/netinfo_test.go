package netinfo

import (
	"net"
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
