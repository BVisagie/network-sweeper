//go:build !linux && !darwin

package discover

import (
	"context"
	"net"
	"time"
)

func arpSweepSupported() bool { return false }

func sweepARP(context.Context, []*net.IPNet, time.Duration) map[string]string {
	return map[string]string{}
}
