package inventory

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// heldHere lists lock paths this process holds. A lock file naming our own
// PID is ours only if it is listed; otherwise it is left over from an earlier
// process that had the same PID (common for PID 1 in containers).
var (
	heldMu   sync.Mutex
	heldHere = map[string]bool{}
)

// acquireLock creates path exclusively and writes this process's PID. A lock
// left by a process that is no longer running is replaced. The stdlib has no
// portable file lock, so this is the single-writer guard.
func acquireLock(path string) error {
	heldMu.Lock()
	defer heldMu.Unlock()
	if heldHere[path] {
		return fmt.Errorf("%s is already open in this process.", strings.TrimSuffix(path, string(os.PathSeparator)+lockName))
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, werr := f.WriteString(strconv.Itoa(os.Getpid()))
			cerr := f.Close()
			if err := errors.Join(werr, cerr); err != nil {
				os.Remove(path)
				return err
			}
			heldHere[path] = true
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("Could not lock %s: %v.", path, err)
		}
		b, _ := os.ReadFile(path)
		pid, perr := strconv.Atoi(strings.TrimSpace(string(b)))
		if perr == nil && pid != os.Getpid() && processAlive(pid) {
			return fmt.Errorf("Another Network Sweeper (PID %d) is using %s.", pid, strings.TrimSuffix(path, string(os.PathSeparator)+lockName))
		}
		// Stale or unreadable lock: the owner is gone.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("Could not replace the stale lock %s: %v.", path, err)
		}
	}
	return fmt.Errorf("Could not lock %s.", path)
}

// releaseLock removes the lock if this process still owns it.
func releaseLock(path string) {
	heldMu.Lock()
	defer heldMu.Unlock()
	if !heldHere[path] {
		return
	}
	delete(heldHere, path)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid == os.Getpid() {
		os.Remove(path)
	}
}
