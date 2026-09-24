package inventory

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

var t0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func snapAt(id string, minute int, gwMAC string, hosts []discover.Host, ports []scan.Result) *Snapshot {
	return &Snapshot{
		ID: id, State: "completed", FinishedAt: t0.Add(time.Duration(minute) * time.Minute),
		Coverage:  Coverage{Ranges: []string{"192.168.1.0/24"}, Methods: []string{"tcp", "arp-cache"}},
		GatewayIP: "192.168.1.1", GatewayMAC: gwMAC, GatewaySubnet: "192.168.1.0/24",
		Hosts: hosts, Ports: ports,
	}
}

func deviceOf(t *testing.T, s *Store, snap *Snapshot, ip string) Device {
	t.Helper()
	for _, h := range snap.Hosts {
		if h.IP == ip {
			d, ok := s.Device(h.DeviceID)
			if !ok {
				t.Fatalf("%s: device %q missing", ip, h.DeviceID)
			}
			return d
		}
	}
	t.Fatalf("%s not in snapshot", ip)
	return Device{}
}

// TestIdentityAndComparison covers the identity rules that must not merge
// different machines, and comparisons that must not invent disappearances.
func TestIdentityAndComparison(t *testing.T) {
	s := Memory(ModeEphemeral, "")
	gw := "aa:aa:aa:aa:aa:01"

	s1 := snapAt("s1", 0, gw, []discover.Host{
		{IP: "192.168.1.10", MAC: "00:11:22:33:44:55"},
		{IP: "192.168.1.20", MAC: "00:11:22:33:44:66"},
	}, []scan.Result{{IP: "192.168.1.20", Ports: []scan.OpenPort{{Port: 22, Service: "SSH"}}}})
	if err := s.Record(s1); err != nil {
		t.Fatal(err)
	}
	laptop := deviceOf(t, s, s1, "192.168.1.10")
	name := "Laptop"
	if _, err := s.Annotate(laptop.ID, Annotation{Name: &name}); err != nil {
		t.Fatal(err)
	}

	// DHCP reuse: a different MAC now holds .10; the laptop moved to .11.
	// Port 22 on .20 refused this time, so its closure is supported.
	s2 := snapAt("s2", 10, gw, []discover.Host{
		{IP: "192.168.1.10", MAC: "00:99:99:99:99:99"},
		{IP: "192.168.1.11", MAC: "00:11:22:33:44:55"},
		{IP: "192.168.1.20", MAC: "00:11:22:33:44:66"},
	}, []scan.Result{{IP: "192.168.1.20", Closed: []int{22}}})
	if err := s.Record(s2); err != nil {
		t.Fatal(err)
	}
	if d := deviceOf(t, s, s2, "192.168.1.10"); d.ID == laptop.ID || d.Name != "" {
		t.Fatalf("reused address inherited the laptop: %+v", d)
	}
	if d := deviceOf(t, s, s2, "192.168.1.11"); d.ID != laptop.ID || d.Name != "Laptop" {
		t.Fatalf("laptop not followed across addresses: %+v", d)
	}
	c, err := s.Compare(s2.ProfileID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AddressChanges) != 1 || c.AddressChanges[0].From != "192.168.1.10" || c.AddressChanges[0].To != "192.168.1.11" {
		t.Fatalf("address changes: %+v", c.AddressChanges)
	}
	if len(c.NewDevices) != 1 || len(c.ClosedServices) != 1 || c.ClosedServices[0].Port != 22 {
		t.Fatalf("new=%+v closed=%+v", c.NewDevices, c.ClosedServices)
	}

	// A canceled scan that saw only one host proves nothing about the others.
	s3 := snapAt("s3", 20, gw, []discover.Host{{IP: "192.168.1.11", MAC: "00:11:22:33:44:55"}}, nil)
	s3.State, s3.Partial = "canceled", true
	if err := s.Record(s3); err != nil {
		t.Fatal(err)
	}
	c, err = s.Compare(s3.ProfileID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ClosedServices) != 0 || len(c.NotObserved) != 2 {
		t.Fatalf("partial scan: closed=%+v notObserved=%+v", c.ClosedServices, c.NotObserved)
	}
	for _, n := range c.NotObserved {
		if !strings.Contains(n.Note, "partial") {
			t.Fatalf("not-observed note should flag the partial scan: %q", n.Note)
		}
	}

	// Same subnet behind a different gateway is another network: no merge.
	other := snapAt("s4", 30, "bb:bb:bb:bb:bb:02", []discover.Host{{IP: "192.168.1.11", MAC: "00:11:22:33:44:55"}}, nil)
	if err := s.Record(other); err != nil {
		t.Fatal(err)
	}
	if other.ProfileID == s3.ProfileID {
		t.Fatal("identical subnets behind different gateways share a profile")
	}
	if d := deviceOf(t, s, other, "192.168.1.11"); d.ID == laptop.ID {
		t.Fatal("device merged across networks")
	}

	// One MAC answering for several addresses (an extender) splits by address.
	ext := snapAt("s5", 40, gw, []discover.Host{
		{IP: "192.168.1.30", MAC: "00:ee:ee:ee:ee:ee"},
		{IP: "192.168.1.31", MAC: "00:ee:ee:ee:ee:ee"},
	}, nil)
	if err := s.Record(ext); err != nil {
		t.Fatal(err)
	}
	a, b := deviceOf(t, s, ext, "192.168.1.30"), deviceOf(t, s, ext, "192.168.1.31")
	if a.ID == b.ID || a.Basis != BasisAddress || len(a.Uncertain) == 0 {
		t.Fatalf("shared MAC merged or not flagged: %+v %+v", a, b)
	}
}

// TestStorageRecovery checks that saved data survives a restart, that damaged
// or newer files are left untouched, and that a second instance is locked out.
func TestStorageRecovery(t *testing.T) {
	dir := t.TempDir()
	// A lock naming a live process (our parent) keeps this process out.
	if err := os.WriteFile(filepath.Join(dir, lockName), []byte(strconv.Itoa(os.Getppid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := Open(dir).Status(); st.Mode != ModeUnavailable || !strings.Contains(st.Reason, "Another Network Sweeper") {
		t.Fatalf("live lock ignored: %+v", st)
	}
	os.Remove(filepath.Join(dir, lockName))
	s := Open(dir)
	if st := s.Status(); st.Mode != ModePersistent {
		t.Fatalf("open: %+v", st)
	}
	if st := Open(dir).Status(); st.Mode != ModeUnavailable {
		t.Fatalf("second open in this process not locked out: %+v", st)
	}
	snap := snapAt("s1", 0, "aa:aa:aa:aa:aa:01", []discover.Host{{IP: "192.168.1.10", MAC: "00:11:22:33:44:55"}}, nil)
	if err := s.Record(snap); err != nil {
		t.Fatal(err)
	}
	notes := "under the desk"
	if _, err := s.Annotate(snap.Hosts[0].DeviceID, Annotation{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(snapAt("s2", 5, "aa:aa:aa:aa:aa:01", []discover.Host{{IP: "192.168.1.10", MAC: "00:11:22:33:44:55"}}, nil)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Restart restores annotations and history.
	s = Open(dir)
	d, ok := s.Device(snap.Hosts[0].DeviceID)
	if !ok || d.Notes != notes || len(s.Scans("")) != 2 {
		t.Fatalf("restart lost data: ok=%v device=%+v scans=%d", ok, d, len(s.Scans("")))
	}

	// A damaged snapshot gives an actionable error, not a crash or overwrite.
	if err := os.WriteFile(filepath.Join(dir, scansDir, "s1.json"), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Compare(d.ProfileID, "", ""); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("damaged snapshot: %v", err)
	}
	s.Close()

	// A damaged index, or one from a newer version, is reported and left as is.
	index := filepath.Join(dir, inventoryName)
	for _, content := range []string{`{"version":1,"devices":[`, `{"version":99}`} {
		if err := os.WriteFile(index, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s = Open(dir)
		if st := s.Status(); st.Mode != ModeUnavailable {
			t.Fatalf("%q: expected unavailable, got %+v", content, st)
		}
		if err := s.Record(snapAt("s9", 9, "", nil, nil)); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(index); string(got) != content {
			t.Fatalf("%q was overwritten with %q", content, got)
		}
		s.Close()
	}
}
