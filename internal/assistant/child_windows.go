//go:build windows

package assistant

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// childID is who an AI CLI runs as. On Windows, "Run as administrator" keeps
// the user's own profile, so the CLI already finds its login.
type childID struct {
	home string
}

func childIdentity() (*childID, error) {
	home, _ := os.UserHomeDir()
	return &childID{home: home}, nil
}

func (c *childID) chown(string) error             { return nil }
func (c *childID) environ(base []string) []string { return base }

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
	processSetQuota                   = 0x0100
)

// Layouts of JOBOBJECT_BASIC_LIMIT_INFORMATION, IO_COUNTERS and
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
type jobBasicLimit struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobExtendedLimit struct {
	BasicLimitInformation jobBasicLimit
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// tree holds the CLI and everything it starts in a Job Object that kills
// all of them when stopped, or when the job is closed after the turn.
type tree struct {
	mu  sync.Mutex
	job syscall.Handle
}

func (c *childID) apply(cmd *exec.Cmd) *tree {
	t := &tree{}
	cmd.Cancel = func() error {
		if t.terminate() {
			return nil
		}
		return cmd.Process.Kill()
	}
	return t
}

// started puts the new process in a kill-on-close job. Processes it starts
// from then on join the job too. It fails closed: a CLI that cannot be
// contained does not run.
func (t *tree) started(cmd *exec.Cmd) error {
	job, _, err := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		return fmt.Errorf("could not contain the AI process: %v", err)
	}
	info := jobExtendedLimit{BasicLimitInformation: jobBasicLimit{LimitFlags: jobObjectLimitKillOnJobClose}}
	if ok, _, err := procSetInformationJobObject.Call(job, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); ok == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("could not contain the AI process: %v", err)
	}
	h, err := syscall.OpenProcess(processSetQuota|syscall.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("could not contain the AI process: %v", err)
	}
	ok, _, err := procAssignProcessToJobObject.Call(job, uintptr(h))
	syscall.CloseHandle(h)
	if ok == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return fmt.Errorf("could not contain the AI process: %v", err)
	}
	t.mu.Lock()
	t.job = syscall.Handle(job)
	t.mu.Unlock()
	return nil
}

// terminate kills every process in the job; false when there is no job.
func (t *tree) terminate() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job == 0 {
		return false
	}
	procTerminateJobObject.Call(uintptr(t.job), 1)
	return true
}

// close releases the job; kill-on-close ends anything the CLI left running.
func (t *tree) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job != 0 {
		syscall.CloseHandle(t.job)
		t.job = 0
	}
}
