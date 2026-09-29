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

// TestHelperProcess is not a test: the tree tests run the test binary as a
// pretend CLI that starts a grandchild ("leaf"), then either keeps running
// ("tree") or exits at once ("tree-exit").
func TestHelperProcess(t *testing.T) {
	switch mode := os.Getenv("GO_NS_HELPER"); mode {
	case "tree", "tree-exit":
		leaf := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		leaf.Env = append(os.Environ(), "GO_NS_HELPER=leaf")
		if err := leaf.Start(); err != nil {
			os.Exit(2)
		}
		_ = os.WriteFile(os.Getenv("GO_NS_PIDFILE"), []byte(strconv.Itoa(leaf.Process.Pid)), 0o600)
		if mode == "tree" {
			time.Sleep(time.Minute)
		}
		os.Exit(0)
	case "leaf":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestStopKillsTheWholeProcessTree(t *testing.T) {
	r, pidFile := helperRunner(t, "tree")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.exec(ctx, "", "-test.run=^TestHelperProcess$")
		done <- err
	}()
	pid := waitForPID(t, pidFile, cancel)
	cancel()
	if err := <-done; err == nil || err.Error() != "stopped" {
		t.Errorf("exec returned %v, want stopped", err)
	}
	requireGone(t, pid, "the CLI's child outlived Stop")
}

// A CLI that finishes normally but leaves a child running must not leave it
// behind once the turn is over.
func TestFinishedTurnLeavesNoChildBehind(t *testing.T) {
	r, pidFile := helperRunner(t, "tree-exit")
	if _, err := r.exec(context.Background(), "", "-test.run=^TestHelperProcess$"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	requireGone(t, waitForPID(t, pidFile, func() {}), "the CLI's child outlived a finished turn")
}

func helperRunner(t *testing.T, mode string) (runner, string) {
	pidFile := filepath.Join(t.TempDir(), "leaf.pid")
	return runner{bin: os.Args[0], dir: t.TempDir(), id: &childID{},
		env: append(os.Environ(), "GO_NS_HELPER="+mode, "GO_NS_PIDFILE="+pidFile)}, pidFile
}

func waitForPID(t *testing.T, pidFile string, cancel func()) int {
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
			if pid, err := strconv.Atoi(string(b)); err == nil {
				return pid
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the pretend CLI never started its child")
		}
	}
}

func requireGone(t *testing.T, pid int, msg string) {
	for deadline := time.Now().Add(10 * time.Second); processAlive(pid); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
			t.Fatal(msg)
		}
	}
}
