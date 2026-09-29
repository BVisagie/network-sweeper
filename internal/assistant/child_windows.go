//go:build windows

package assistant

import (
	"os"
	"os/exec"
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

func (c *childID) apply(*exec.Cmd)                {}
func (c *childID) chown(string) error             { return nil }
func (c *childID) environ(base []string) []string { return base }
