package discover

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

// Ping attempts an ICMP echo via the system ping utility.
// On Windows this often works without elevation; on Linux/macOS it typically
// requires privileges and fails quickly otherwise.
func Ping(ctx context.Context, ip net.IP, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		ms := int(timeout / time.Millisecond)
		if ms < 100 {
			ms = 100
		}
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(ms), ip.String())
	case "darwin":
		// -W is timeout in milliseconds on macOS.
		ms := int(timeout / time.Millisecond)
		if ms < 100 {
			ms = 100
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(ms), ip.String())
	default: // linux: -W is timeout in seconds (integer)
		sec := int((timeout + time.Second - 1) / time.Second)
		if sec < 1 {
			sec = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(sec), ip.String())
	}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
