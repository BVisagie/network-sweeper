package scan

import (
	"context"
	"testing"
	"time"
)

func TestServiceNames(t *testing.T) {
	if ServiceNames[22] != "SSH" {
		t.Fatal(ServiceNames[22])
	}
	if ServiceNames[445] != "SMB" {
		t.Fatal(ServiceNames[445])
	}
}

func TestScanHostsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanHosts(ctx, []string{"127.0.0.1"}, 50*time.Millisecond, 2)
	// canceled context should not panic; error may be nil or context error depending on timing
	_ = err
}
