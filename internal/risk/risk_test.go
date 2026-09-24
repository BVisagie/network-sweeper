package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// TestEvaluateEvidenceMatrix checks that severity follows evidence: an open
// port alone is inferred and modest, a protocol answer is confirmed, a silent
// probe stays inferred and says so, and a gateway gets one finding per port.
func TestEvaluateEvidenceMatrix(t *testing.T) {
	cases := []struct {
		name       string
		host       discover.Host
		port       scan.OpenPort
		wantID     string
		severity   string
		confidence string
		category   string
		unknownHas string
	}{
		{"telnet port only", discover.Host{IP: "10.0.0.1"}, scan.OpenPort{Port: 23},
			"telnet-open-10.0.0.1", SeverityMedium, ConfidenceInferred, CategoryExposure, "Only the TCP port"},
		{"telnet answered", discover.Host{IP: "10.0.0.1"}, scan.OpenPort{Port: 23, Protocol: "Telnet", Probe: "answered"},
			"telnet-open-10.0.0.1", SeverityHigh, ConfidenceConfirmed, CategoryIssue, "trusted hosts"},
		{"telnet probe silent", discover.Host{IP: "10.0.0.1"}, scan.OpenPort{Port: 23, Probe: "no-answer"},
			"telnet-open-10.0.0.1", SeverityMedium, ConfidenceInferred, CategoryExposure, "no recognizable answer"},
		{"docker port only", discover.Host{IP: "10.0.0.2"}, scan.OpenPort{Port: 2375},
			"docker-api-10.0.0.2", SeverityMedium, ConfidenceInferred, CategoryExposure, ""},
		{"docker answered", discover.Host{IP: "10.0.0.2"}, scan.OpenPort{Port: 2375, Protocol: "Docker API", Probe: "answered"},
			"docker-api-10.0.0.2", SeverityCritical, ConfidenceConfirmed, CategoryIssue, ""},
		{"smb port only", discover.Host{IP: "10.0.0.3"}, scan.OpenPort{Port: 445},
			"smb-open-10.0.0.3", SeverityLow, ConfidenceInferred, CategoryExposure, "not checked"},
		{"database port only", discover.Host{IP: "10.0.0.4"}, scan.OpenPort{Port: 3306},
			"mysql-open-10.0.0.4", SeverityLow, ConfidenceInferred, CategoryExposure, ""},
		{"rdp on gateway", discover.Host{IP: "10.0.0.254", IsGateway: true}, scan.OpenPort{Port: 3389},
			"gateway-mgmt-3389-10.0.0.254", SeverityMedium, ConfidenceInferred, CategoryExposure, ""},
		{"telnet answered on gateway", discover.Host{IP: "10.0.0.254", IsGateway: true}, scan.OpenPort{Port: 23, Protocol: "Telnet", Probe: "answered"},
			"gateway-mgmt-23-10.0.0.254", SeverityHigh, ConfidenceConfirmed, CategoryIssue, ""},
	}
	for _, c := range cases {
		c.host.Hostname = "named" // keep the unidentified-device finding out of the way
		fs := Evaluate([]discover.Host{c.host}, []scan.Result{{IP: c.host.IP, Ports: []scan.OpenPort{c.port}}})
		var got []Finding
		for _, f := range fs {
			if f.Port == c.port.Port {
				got = append(got, f)
			}
		}
		if len(got) != 1 {
			t.Errorf("%s: %d findings for port %d, want exactly 1: %+v", c.name, len(got), c.port.Port, got)
			continue
		}
		f := got[0]
		if f.ID != c.wantID || f.Severity != c.severity || f.Confidence != c.confidence || f.Category != c.category {
			t.Errorf("%s: got %s %s/%s/%s, want %s %s/%s/%s", c.name,
				f.ID, f.Severity, f.Confidence, f.Category, c.wantID, c.severity, c.confidence, c.category)
		}
		if !strings.Contains(f.Unknown, c.unknownHas) {
			t.Errorf("%s: unknown %q does not mention %q", c.name, f.Unknown, c.unknownHas)
		}
		if len(f.Evidence) == 0 || f.Evidence[0].Method != "tcp-connect" {
			t.Errorf("%s: missing tcp-connect evidence: %+v", c.name, f.Evidence)
		}
		if c.confidence == ConfidenceConfirmed && len(f.Evidence) < 2 {
			t.Errorf("%s: confirmed finding lacks response evidence: %+v", c.name, f.Evidence)
		}
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
