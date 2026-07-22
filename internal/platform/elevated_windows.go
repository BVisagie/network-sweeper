//go:build windows

package platform

import "os/exec"

// IsElevated reports whether the process is running elevated (Administrator).
// Uses `net session`, which fails without elevation.
func IsElevated() bool {
	return exec.Command("net", "session").Run() == nil
}
