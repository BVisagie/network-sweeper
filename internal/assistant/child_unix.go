//go:build !windows

package assistant

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// childID is who an AI CLI runs as. Under sudo that is the invoking user,
// never root: the scanner keeps its privileges, the AI does not get them.
type childID struct {
	cred *syscall.Credential // nil: run as this process
	home string
	user string
}

func childIdentity() (*childID, error) {
	return resolveChild(os.Geteuid(), os.Getenv, user.LookupId)
}

// resolveChild picks the identity from the effective UID and sudo's
// variables. Root without SUDO_UID has no user to hand the AI to.
func resolveChild(euid int, getenv func(string) string, lookup func(string) (*user.User, error)) (*childID, error) {
	if euid != 0 {
		home, _ := os.UserHomeDir()
		return &childID{home: home}, nil
	}
	uidStr, gidStr := getenv("SUDO_UID"), getenv("SUDO_GID")
	uid, err1 := strconv.ParseUint(uidStr, 10, 32)
	gid, err2 := strconv.ParseUint(gidStr, 10, 32)
	if err1 != nil || err2 != nil || uid == 0 {
		return nil, errors.New("Network Sweeper is running as root without sudo, and will not run an AI agent as root. Start it with sudo from your own account, or use a local model server")
	}
	u, err := lookup(uidStr)
	if err != nil {
		return nil, errors.New("could not look up the account that started sudo: " + err.Error())
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				cred.Groups = append(cred.Groups, uint32(n))
			}
		}
	}
	return &childID{cred: cred, home: u.HomeDir, user: u.Username}, nil
}

// apply runs the command in its own process group, as the child identity,
// and kills the whole group when the request is stopped.
func (c *childID) apply(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: c.cred}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func (c *childID) chown(path string) error {
	if c.cred == nil {
		return nil
	}
	return os.Chown(path, int(c.cred.Uid), int(c.cred.Gid))
}

// environ returns the child's environment. Under sudo it is rebuilt for the
// invoking user, so the CLI finds that user's login and tools.
func (c *childID) environ(base []string) []string {
	if c.cred == nil {
		return base
	}
	var env []string
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if k == "LANG" || k == "TERM" || k == "TZ" || strings.HasPrefix(k, "LC_") {
			env = append(env, kv)
		}
	}
	path := []string{}
	for _, d := range []string{".local/bin", ".local/share/mise/shims", ".npm-global/bin", ".bun/bin", ".volta/bin", ".cargo/bin"} {
		path = append(path, filepath.Join(c.home, d))
	}
	path = append(path, "/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin")
	env = append(env, "HOME="+c.home, "USER="+c.user, "LOGNAME="+c.user, "PATH="+strings.Join(path, ":"))
	if run := "/run/user/" + strconv.Itoa(int(c.cred.Uid)); isDir(run) {
		env = append(env, "XDG_RUNTIME_DIR="+run)
	}
	return env
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
