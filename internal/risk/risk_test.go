package risk

import (
	"strings"
	"testing"

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
