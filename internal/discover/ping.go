package discover

import (
	"context"
	"net"
	"os/exec"
	"runtime"
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
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", itoa(ms), ip.String())
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "500", ip.String())
	default: // linux
		sec := int(timeout / time.Second)
		if sec < 1 {
			sec = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", itoa(sec), ip.String())
	}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
