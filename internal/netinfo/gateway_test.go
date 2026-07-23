package netinfo

import "testing"

func TestParseGatewayDarwin(t *testing.T) {
	sample := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
`
	g := ParseGatewaySample("darwin", sample)
	if g != "192.168.1.1" {
		t.Fatalf("got %q", g)
	}
}

func TestParseGatewayLinux(t *testing.T) {
	sample := `default via 10.0.0.1 dev eth0 proto dhcp metric 100`
	g := ParseGatewaySample("linux", sample)
	if g != "10.0.0.1" {
		t.Fatalf("got %q", g)
	}
}

func TestCountUsableHosts(t *testing.T) {
	nets, err := ParseCIDRList("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if CountUsableHosts(nets[0]) != 254 {
		t.Fatalf("got %d", CountUsableHosts(nets[0]))
	}
	hosts := HostsInCIDR(nets[0], 10)
	if len(hosts) != 10 {
		t.Fatalf("got %d", len(hosts))
	}
}

func TestLooksLikeCommonRouter(t *testing.T) {
	if !LooksLikeCommonRouter("192.168.1.1") {
		t.Fatal(".1")
	}
	if LooksLikeCommonRouter("192.168.1.50") {
		t.Fatal(".50")
	}
}
