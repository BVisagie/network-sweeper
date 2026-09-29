//go:build !windows

package assistant

import (
	"errors"
	"os/user"
	"testing"
)

func TestAIRunsAsTheSudoUserNeverRoot(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	lookup := func(uid string) (*user.User, error) {
		if uid != "1000" {
			return nil, errors.New("no such user")
		}
		return &user.User{Uid: "1000", Gid: "1000", Username: "bob", HomeDir: "/home/bob"}, nil
	}

	id, err := resolveChild(0, env(map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1000"}), lookup)
	if err != nil || id.cred == nil || id.cred.Uid != 1000 || id.cred.Gid != 1000 || id.home != "/home/bob" {
		t.Fatalf("under sudo: id=%+v err=%v", id, err)
	}
	for _, kv := range id.environ([]string{"HOME=/root", "LANG=C.UTF-8", "SUDO_COMMAND=x"}) {
		if kv == "HOME=/root" || kv == "SUDO_COMMAND=x" {
			t.Errorf("root's environment leaked to the AI: %s", kv)
		}
	}

	for _, vars := range []map[string]string{{}, {"SUDO_UID": "0", "SUDO_GID": "0"}, {"SUDO_UID": "x", "SUDO_GID": "1"}} {
		if _, err := resolveChild(0, env(vars), lookup); err == nil {
			t.Errorf("root with %v was allowed to run the AI", vars)
		}
	}

	if id, err := resolveChild(1000, env(nil), lookup); err != nil || id.cred != nil {
		t.Errorf("normal user: id=%+v err=%v", id, err)
	}
}
