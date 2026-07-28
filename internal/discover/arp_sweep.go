package discover

import (
	"context"
	"net"
	"time"
)

// ARPSweepSupported reports whether this OS implements elevated active ARP.
func ARPSweepSupported() bool {
	return arpSweepSupported()
}

// SweepARP sends ARP who-has probes for usable addresses in targets and returns
// IP → MAC for replies. No-op when unsupported or ctx canceled.
func SweepARP(ctx context.Context, targets []*net.IPNet, timeout time.Duration) map[string]string {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	return sweepARP(ctx, targets, timeout)
}
