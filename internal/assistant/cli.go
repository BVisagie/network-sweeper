package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const outputCap = 1 << 20

// cliBackend is an AI CLI run once per turn, as the invoking user, in an empty
// temp directory, with the transcript on stdin.
type cliBackend struct {
	id, label, name, override, note string
	// prepare checks this CLI version can be locked down, and returns the
	// arguments for one turn. out is a file the CLI may write its reply to.
	prepare func(ctx context.Context, run runner, out string) ([]string, error)
	// parse turns stdout (or the out file's content) into the reply.
	parse func(stdout, outFile []byte) (string, error)
}

func (s *Service) claude() *cliBackend {
	return &cliBackend{
		id: "claude", label: "Claude CLI", name: "claude", override: s.opt.ClaudePath,
		note: "Sends what you share to Anthropic under your Claude login. All of its tools are switched off.",
		prepare: func(context.Context, runner, string) ([]string, error) {
			// --tools "" removes every tool, so the model can only answer in text.
			return []string{"-p", "--tools", "", "--strict-mcp-config", "--no-session-persistence", "--output-format", "json"}, nil
		},
		parse: parseClaude,
	}
}

func (s *Service) codex() *cliBackend {
	return &cliBackend{
		id: "codex", label: "Codex CLI", name: "codex", override: s.opt.CodexPath,
		note:    "Sends what you share to OpenAI under your Codex login. Its shell and other tools are switched off.",
		prepare: prepareCodex,
		parse: func(_, outFile []byte) (string, error) {
			if r := strings.TrimSpace(string(outFile)); r != "" {
				return r, nil
			}
			return "", errors.New("Codex returned no reply")
		},
	}
}

func parseClaude(stdout, _ []byte) (string, error) {
	var r struct {
		Result  string `json:"result"`
		IsError bool   `json:"is_error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &r); err != nil {
		return "", fmt.Errorf("could not read Claude's reply: %v", err)
	}
	if r.IsError {
		return "", fmt.Errorf("Claude: %s", strings.TrimSpace(r.Result))
	}
	return strings.TrimSpace(r.Result), nil
}

// codexOff are the Codex features that could run code, browse, or reach
// other tools. A version that does not list all of them is refused, so a
// renamed switch can never silently leave a tool on.
var codexOff = []string{"shell_tool", "unified_exec", "code_mode_host", "browser_use", "computer_use", "in_app_browser", "apps", "plugins"}

func prepareCodex(ctx context.Context, run runner, out string) ([]string, error) {
	listed, err := run.output(ctx, 20*time.Second, "features", "list")
	if err != nil {
		return nil, fmt.Errorf("could not list Codex features: %v", err)
	}
	known := map[string]bool{}
	for _, line := range strings.Split(string(listed), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			known[f[0]] = true
		}
	}
	args := []string{"exec", "--sandbox", "read-only", "--ephemeral", "--skip-git-repo-check",
		"-c", "mcp_servers={}", "-c", `web_search="disabled"`}
	for _, f := range codexOff {
		if !known[f] {
			return nil, fmt.Errorf("this Codex version has no %q switch, so its tools cannot be verified as off; update Network Sweeper or use another backend", f)
		}
		args = append(args, "--disable", f)
	}
	return append(args, "-C", run.dir, "--output-last-message", out, "-"), nil
}

func (b *cliBackend) status(ctx context.Context) Status {
	st := Status{ID: b.id, Label: b.label, Note: b.note}
	run, err := b.runner()
	if err != nil {
		st.Reason = err.Error()
		return st
	}
	defer run.close()
	v, err := run.output(ctx, 20*time.Second, "--version")
	if err != nil {
		st.Reason = fmt.Sprintf("%s did not start: %v", b.name, err)
		return st
	}
	st.Version = firstLine(string(v))
	st.Available = true
	return st
}

func (b *cliBackend) ask(ctx context.Context, text string) (string, error) {
	run, err := b.runner()
	if err != nil {
		return "", err
	}
	defer run.close()
	out := filepath.Join(run.dir, "reply.txt")
	args, err := b.prepare(ctx, run, out)
	if err != nil {
		return "", err
	}
	stdout, err := run.exec(ctx, text, args...)
	file, _ := os.ReadFile(out)
	if err != nil {
		// Claude reports errors such as "Not logged in" in its JSON result.
		if _, perr := b.parse(stdout, file); perr != nil && len(stdout) > 0 && b.id == "claude" {
			return "", perr
		}
		return "", err
	}
	return b.parse(stdout, file)
}

// runner runs one CLI binary as the child identity in its own temp dir.
type runner struct {
	bin, dir string
	id       *childID
	env      []string
}

func (b *cliBackend) runner() (runner, error) {
	id, err := childIdentity()
	if err != nil {
		return runner{}, err
	}
	bin, err := findBinary(b.name, b.override, id.home)
	if err != nil {
		return runner{}, err
	}
	dir, err := os.MkdirTemp("", "network-sweeper-ai-")
	if err != nil {
		return runner{}, err
	}
	if err := id.chown(dir); err != nil {
		os.RemoveAll(dir)
		return runner{}, err
	}
	return runner{bin: bin, dir: dir, id: id, env: id.environ(cleanEnv(os.Environ()))}, nil
}

func (r runner) close() { os.RemoveAll(r.dir) }

func (r runner) output(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.exec(ctx, "", args...)
}

func (r runner) exec(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.dir
	cmd.Env = r.env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr capped
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	r.id.apply(cmd)
	err := cmd.Run()
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("the AI took too long and was stopped")
		}
		return nil, errors.New("stopped")
	}
	if err != nil {
		msg := firstLine(stderr.String())
		if msg == "" {
			msg = firstLine(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), fmt.Errorf("%s failed: %s", filepath.Base(r.bin), msg)
	}
	return stdout.Bytes(), nil
}

// capped keeps the first outputCap bytes and discards the rest.
type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := outputCap - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

var _ io.Writer = (*capped)(nil)

// findBinary looks on PATH, then in the usual per-user install folders of the
// invoking user (sudo resets PATH).
func findBinary(name, override, home string) (string, error) {
	if override != "" {
		if st, err := os.Stat(override); err != nil || st.IsDir() {
			return "", fmt.Errorf("%s not found at %s", name, override)
		}
		return override, nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	if runtime.GOOS != "windows" {
		var dirs []string
		if home != "" {
			for _, d := range []string{".local/bin", ".local/share/mise/shims", ".npm-global/bin", ".bun/bin", ".volta/bin", ".cargo/bin"} {
				dirs = append(dirs, filepath.Join(home, d))
			}
		}
		dirs = append(dirs, "/usr/local/bin", "/opt/homebrew/bin", "/usr/bin")
		for _, d := range dirs {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s is not installed, or not on PATH (start Network Sweeper with -%s-path to point at it)", name, name)
}

// cleanEnv drops the variables a parent Claude Code session sets, so a CLI
// started from inside one does not try to attach to it.
func cleanEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if k == "CLAUDECODE" || k == "CLAUDE_PID" || k == "CLAUDE_EFFORT" || strings.HasPrefix(k, "CLAUDE_CODE_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
