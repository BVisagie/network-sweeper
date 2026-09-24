package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// errLocked means another open file already holds the OS lock.
var errLocked = errors.New("locked")

// acquireLock takes an OS-backed exclusive lock on path (flock on Unix, an
// unshared handle on Windows). The OS drops it when the process exits, so a
// crash never leaves a stale lock, and there is no window in which a lock
// being created can be mistaken for an abandoned one. The PID written into the
// file is only for the message another instance shows.
func acquireLock(path string) (*os.File, error) {
	f, err := lockFile(path)
	if errors.Is(err, errLocked) {
		who := "Another Network Sweeper"
		if b, rerr := os.ReadFile(path); rerr == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil {
				who += fmt.Sprintf(" (PID %d)", pid)
			}
		}
		return nil, fmt.Errorf("%s is using %s.", who, filepath.Dir(path))
	}
	if err != nil {
		return nil, fmt.Errorf("Could not lock %s: %v.", path, err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return f, nil
}
