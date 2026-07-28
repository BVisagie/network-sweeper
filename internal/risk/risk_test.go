package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

func TestEvaluateTelnet(t *testing.T) {
	hosts := []discover.Host{{IP: "192.168.1.10"}}
	results := []scan.Result{{
		IP:    "192.168.1.10",
		Ports: []scan.OpenPort{{Port: 23, Service: "Telnet"}},
	}}
	f := Evaluate(hosts, results)
	found := false
	for _, x := range f {
		if x.Severity == SeverityCritical && x.Port == 23 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical telnet finding")
	}
}

func TestEvaluateIdentificationInfo(t *testing.T) {
	hosts := []discover.Host{{IP: "192.168.1.20"}}
	f := Evaluate(hosts, nil)
	foundInfo := false
	for _, x := range f {
		if x.ID == "unknown-device-192.168.1.20" && x.Severity == SeverityInfo {
			foundInfo = true
		}
		if strings.Contains(x.ID, "unknown-mac") {
			t.Fatal("mac-unknown finding should be demoted/removed")
		}
	}
	if !foundInfo {
		t.Fatal("expected unidentified device info finding")
	}
}

func TestEvaluateSkipsUnknownWhenHint(t *testing.T) {
	hosts := []discover.Host{{IP: "192.168.1.21"}}
	results := []scan.Result{{
		IP:    "192.168.1.21",
		Ports: []scan.OpenPort{{Port: 80, Service: "HTTP", HTTPTitle: "Router"}},
	}}
	for _, x := range Evaluate(hosts, results) {
		if x.ID == "unknown-device-192.168.1.21" {
			t.Fatal("should not emit unknown-device when HTTP title present")
		}
	}
}

func TestEvaluateDatabaseAndHTTPAlt(t *testing.T) {
	hosts := []discover.Host{{IP: "10.0.0.5"}}
	results := []scan.Result{{
		IP: "10.0.0.5",
		Ports: []scan.OpenPort{
			{Port: 3306, Service: "MySQL"},
			{Port: 8080, Service: "HTTP-Proxy"},
		},
	}}
	want := map[string]bool{"mysql-open-10.0.0.5": false, "http-alt-8080-10.0.0.5": false}
	for _, x := range Evaluate(hosts, results) {
		if _, ok := want[x.ID]; ok {
			want[x.ID] = true
		}
	}
	for id, ok := range want {
		if !ok {
			t.Fatalf("missing finding %s", id)
		}
	}
}

func TestEvaluateGatewayContext(t *testing.T) {
	hosts := []discover.Host{{IP: "192.168.1.1", IsGateway: true}}
	results := []scan.Result{{
		IP:    "192.168.1.1",
		Ports: []scan.OpenPort{{Port: 3389, Service: "RDP"}},
	}}
	found := false
	for _, x := range Evaluate(hosts, results) {
		if x.ID == "gateway-mgmt-3389-192.168.1.1" && x.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatal("expected gateway management finding")
	}
}

func TestEvaluateUPnPAndSNMP(t *testing.T) {
	hosts := []discover.Host{
		{IP: "10.0.0.5", UPnP: true, UPnPFriendlyName: "Living Room TV", Hostname: "tv"},
		{IP: "10.0.0.6", SNMPPublic: true, SNMPSysDescr: "Printer", Hostname: "printer"},
	}
	f := Evaluate(hosts, nil)
	var upnp, snmp bool
	for _, x := range f {
		if x.ID == "upnp-ssdp-10.0.0.5" {
			upnp = true
		}
		if x.ID == "snmp-public-10.0.0.6" && x.Severity == SeverityMedium && x.Port == 161 {
			snmp = true
		}
	}
	if !upnp || !snmp {
		t.Fatalf("upnp=%v snmp=%v findings=%v", upnp, snmp, f)
	}
}

func TestEvaluateTLSEnrichment(t *testing.T) {
	hosts := []discover.Host{{IP: "10.0.0.8", Hostname: "nas"}}
	results := []scan.Result{{
		IP: "10.0.0.8",
		Ports: []scan.OpenPort{{
			Port:          443,
			Service:       "HTTPS",
			TLSCommonName: "nas.local",
			TLSSelfSigned: true,
			TLSExpired:    true,
			TLSNotAfter:   time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
		}},
	}}
	var selfSigned, expired bool
	for _, x := range Evaluate(hosts, results) {
		if x.ID == "tls-self-signed-443-10.0.0.8" {
			selfSigned = true
		}
		if x.ID == "tls-expired-443-10.0.0.8" && x.Severity == SeverityMedium {
			expired = true
		}
	}
	if !selfSigned || !expired {
		t.Fatalf("selfSigned=%v expired=%v", selfSigned, expired)
	}
}
