//go:build !windows

package assistant

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCLI installs a script named name that records its arguments and stdin.
func fakeCLI(t *testing.T, name, body string) (bin, argsFile, stdinFile string) {
	dir := t.TempDir()
	argsFile, stdinFile = filepath.Join(dir, "args"), filepath.Join(dir, "stdin")
	bin = filepath.Join(dir, name)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + argsFile + "\ncat > " + stdinFile + "\n" + body
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile, stdinFile
}

func TestClaudeRunsWithEveryToolOff(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	bin, argsFile, stdinFile := fakeCLI(t, "claude", `echo '{"type":"result","is_error":false,"result":"Some questions first."}'`)
	s := New(Options{ClaudePath: bin})
	reply, err := s.Ask(context.Background(), Request{
		Backend: "claude", Prompt: "PROMPT-TEXT",
		History: []Message{{"assistant", "Who uses the network?"}, {"user", "A family of four."}},
	})
	if err != nil || reply != "Some questions first." {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--tools\n\n--strict-mcp-config\n") {
		t.Errorf("claude not started with every tool off; args:\n%s", args)
	}
	in, _ := os.ReadFile(stdinFile)
	for _, want := range []string{"PROMPT-TEXT", "### Advisor (you)\n\nWho uses the network?", "### Owner\n\nA family of four."} {
		if !strings.Contains(string(in), want) {
			t.Errorf("transcript lacks %q", want)
		}
	}
}

func TestCodexRefusesWhenAToolSwitchIsMissing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	// This Codex knows every switch except shell_tool.
	features := strings.Join([]string{"unified_exec", "code_mode_host", "browser_use", "computer_use", "in_app_browser", "apps", "plugins"}, " stable false\\n")
	bin, argsFile, _ := fakeCLI(t, "codex", `printf '`+features+` stable false\n'`)
	s := New(Options{CodexPath: bin})
	if st := s.Statuses(context.Background(), "")[1]; st.ID != "codex" || st.Available || !strings.Contains(st.Reason, "shell_tool") {
		t.Errorf("status = %+v, want codex unavailable naming shell_tool", st)
	}
	_, err := s.Ask(context.Background(), Request{Backend: "codex", Prompt: "p"})
	if err == nil || !strings.Contains(err.Error(), "shell_tool") {
		t.Fatalf("err = %v, want a refusal naming shell_tool", err)
	}
	if args, _ := os.ReadFile(argsFile); strings.Contains(string(args), "exec") {
		t.Errorf("codex exec ran although a switch was missing")
	}
}
