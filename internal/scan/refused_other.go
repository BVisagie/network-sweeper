//go:build !windows

package scan

import (
	"errors"
	"syscall"
)

// refused reports whether a dial failed because the host answered with a reset.
func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
