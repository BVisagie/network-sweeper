//go:build !windows

package platform

import "os"

// IsElevated reports whether the process is running as root.
func IsElevated() bool {
	return os.Geteuid() == 0
}
