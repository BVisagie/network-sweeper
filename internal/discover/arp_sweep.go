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
// IP → the distinct MACs that replied, in reply order. More than one MAC for an
// IP means two devices claim the same address. No-op when unsupported or ctx
// canceled.
func SweepARP(ctx context.Context, targets []*net.IPNet, timeout time.Duration) map[string][]string {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	return sweepARP(ctx, targets, timeout)
}

// addReply records mac as an answer for ip unless that MAC already answered.
func addReply(out map[string][]string, ip, mac string) {
	for _, m := range out[ip] {
		if m == mac {
			return
		}
	}
	out[ip] = append(out[ip], mac)
}
