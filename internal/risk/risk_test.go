package risk

import (
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
