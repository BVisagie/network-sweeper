package platform

import (
	"os"
	"runtime"
	"testing"
)

func TestIsElevatedConsistentWithUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows elevation uses net session")
	}
	want := os.Geteuid() == 0
	if IsElevated() != want {
		t.Fatalf("IsElevated=%v want %v", IsElevated(), want)
	}
}
