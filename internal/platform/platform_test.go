package platform

import (
	"os"
	"runtime"
	"testing"
)

func TestSnapshotARPDeferred(t *testing.T) {
	info := Snapshot(true)
	for _, c := range info.Capabilities {
		if c.Name == "Active ARP sweep" && c.Status != "deferred" {
			t.Fatalf("elevated must not mark ARP sweep full, got %q", c.Status)
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
