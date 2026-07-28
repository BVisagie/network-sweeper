package platform

import (
	"os"
	"runtime"
	"testing"

	"github.com/BVisagie/network-sweeper/internal/discover"
)

func TestSnapshotARPStatus(t *testing.T) {
	info := Snapshot(true)
	var arp Capability
	found := false
	for _, c := range info.Capabilities {
		if c.Name == "Active ARP sweep" {
			arp = c
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing Active ARP sweep capability")
	}
	if discover.ARPSweepSupported() {
		if arp.Status != "full" {
			t.Fatalf("elevated unix ARP want full, got %q", arp.Status)
		}
	} else if arp.Status != "deferred" {
		t.Fatalf("unsupported OS must keep ARP deferred when elevated, got %q", arp.Status)
	}

	info2 := Snapshot(false)
	for _, c := range info2.Capabilities {
		if c.Name != "Active ARP sweep" {
			continue
		}
		if discover.ARPSweepSupported() && c.Status != "elevated" {
			t.Fatalf("unprivileged unix ARP want elevated, got %q", c.Status)
		}
		if !discover.ARPSweepSupported() && c.Status != "deferred" {
			t.Fatalf("unsupported OS ARP want deferred, got %q", c.Status)
		}
	}
}

func TestIsElevatedConsistentWithUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows elevation uses net session")
	}
	want := os.Geteuid() == 0
	if IsElevated() != want {
		t.Fatalf("IsElevated=%v want %v", IsElevated(), want)
	}
}
