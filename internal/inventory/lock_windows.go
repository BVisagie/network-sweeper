//go:build windows

package inventory

import (
	"errors"
	"os"
	"syscall"
)

// errorSharingViolation is ERROR_SHARING_VIOLATION; the syscall package does not name it.
const errorSharingViolation = syscall.Errno(32)

// lockFile opens path with no sharing allowed, so no other handle can open it
// until this one closes.
func lockFile(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) {
			return nil, errLocked
		}
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
