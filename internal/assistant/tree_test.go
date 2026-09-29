package assistant

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestHelperProcess is not a test: TestStopKillsTheWholeProcessTree runs the
// test binary as a pretend CLI ("tree") that starts a grandchild ("leaf").
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("GO_NS_HELPER") {
	case "tree":
		leaf := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		leaf.Env = append(os.Environ(), "GO_NS_HELPER=leaf")
		if err := leaf.Start(); err != nil {
			os.Exit(2)
		}
		_ = os.WriteFile(os.Getenv("GO_NS_PIDFILE"), []byte(strconv.Itoa(leaf.Process.Pid)), 0o600)
		time.Sleep(time.Minute)
		os.Exit(0)
	case "leaf":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestStopKillsTheWholeProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "leaf.pid")
	r := runner{bin: os.Args[0], dir: t.TempDir(), id: &childID{},
		env: append(os.Environ(), "GO_NS_HELPER=tree", "GO_NS_PIDFILE="+pidFile)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.exec(ctx, "", "-test.run=^TestHelperProcess$")
		done <- err
	}()

	var pid int
	for deadline := time.Now().Add(30 * time.Second); pid == 0; time.Sleep(50 * time.Millisecond) {
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
			pid, _ = strconv.Atoi(string(b))
		}
		if time.Now().After(deadline) {
			t.Fatal("the pretend CLI never started its child")
		}
	}
	cancel()
	if err := <-done; err == nil || err.Error() != "stopped" {
		t.Errorf("exec returned %v, want stopped", err)
	}
	for deadline := time.Now().Add(10 * time.Second); processAlive(pid); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
			t.Fatal("the CLI's child outlived Stop")
		}
	}
}
