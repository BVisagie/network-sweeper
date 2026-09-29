//go:build !windows

package assistant

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// processAlive treats a zombie as gone: it has exited, only unreaped.
func processAlive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true // no /proc (macOS): signal 0 is the answer
	}
	if i := strings.LastIndexByte(string(stat), ')'); i >= 0 && i+2 < len(stat) {
		return stat[i+2] != 'Z'
	}
	return true
}
