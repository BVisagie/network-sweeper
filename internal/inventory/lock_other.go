//go:build !unix && !windows

package inventory

import (
	"errors"
	"os"
)

func lockFile(string) (*os.File, error) {
	return nil, errors.New("file locking is not supported on this platform")
}
