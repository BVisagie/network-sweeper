//go:build windows

package scan

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is WSAECONNREFUSED; the syscall package does not name it.
const wsaeconnrefused = syscall.Errno(10061)

// refused reports whether a dial failed because the host answered with a reset.
func refused(err error) bool {
	return errors.Is(err, wsaeconnrefused) || errors.Is(err, syscall.ECONNREFUSED)
}
