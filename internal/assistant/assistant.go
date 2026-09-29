// Package assistant hands the analysis prompt to an AI the user already has on
// this computer: the Claude or Codex CLI with every tool switched off, or a
// model server on loopback. The app itself makes no outbound AI calls, and an
// AI CLI never runs as root.
package assistant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Message is one turn after the prompt: "assistant" replies and "user"
// follow-ups, alternating, starting with the first reply.
type Message struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// Status says whether a backend can be used here, and how.
type Status struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Available bool     `json:"available"`
	Version   string   `json:"version,omitempty"`
	Reason    string   `json:"reason,omitempty"` // why it is unavailable
	Note      string   `json:"note,omitempty"`   // where the data goes
	Models    []string `json:"models,omitempty"` // local server only
}

// Request is one turn of a conversation.
type Request struct {
	Backend    string    `json:"backend"`
	Prompt     string    `json:"prompt"`
	History    []Message `json:"history"`
	LocalURL   string    `json:"localUrl"`
	LocalModel string    `json:"localModel"`
}

// Options locate the CLIs when they are not on PATH.
type Options struct {
	ClaudePath string
	CodexPath  string
}

// Service runs one AI request at a time.
type Service struct {
	opt  Options
	busy sync.Mutex
}

// ErrBusy means another request is still running.
var ErrBusy = errors.New("another AI request is still running")

const (
	askTimeout  = 5 * time.Minute
	maxMessages = 60
)

func New(opt Options) *Service { return &Service{opt: opt} }

// Statuses reports every backend. localURL is checked only when set.
func (s *Service) Statuses(ctx context.Context, localURL string) []Status {
	return []Status{s.claude().status(ctx), s.codex().status(ctx), localStatus(ctx, localURL)}
}

// Ask sends one turn and returns the reply.
func (s *Service) Ask(ctx context.Context, req Request) (string, error) {
	if strings.TrimSpace(req.Prompt) == "" {
		return "", errors.New("the prompt is empty")
	}
	if err := checkHistory(req.History); err != nil {
		return "", err
	}
	if !s.busy.TryLock() {
		return "", ErrBusy
	}
	defer s.busy.Unlock()
	ctx, cancel := context.WithTimeout(ctx, askTimeout)
	defer cancel()
	switch req.Backend {
	case "claude":
		return s.claude().ask(ctx, transcript(req.Prompt, req.History))
	case "codex":
		return s.codex().ask(ctx, transcript(req.Prompt, req.History))
	case "local":
		return askLocal(ctx, req)
	}
	return "", fmt.Errorf("unknown AI backend %q", req.Backend)
}

func checkHistory(h []Message) error {
	if len(h) > maxMessages {
		return errors.New("this conversation is too long; start over")
	}
	for i, m := range h {
		want := "assistant"
		if i%2 == 1 {
			want = "user"
		}
		if m.Role != want {
			return errors.New("the conversation is out of order; start over")
		}
	}
	if len(h) > 0 && h[len(h)-1].Role != "user" {
		return errors.New("write a reply before sending")
	}
	return nil
}

// transcript folds the conversation into one text for the CLIs, which run
// each turn from scratch.
func transcript(prompt string, history []Message) string {
	if len(history) == 0 {
		return prompt
	}
	var b strings.Builder
	b.WriteString(prompt)
	b.WriteString("\n\n## Conversation so far\n\nYou (the advisor) and the owner have already exchanged the messages below. Continue the conversation by replying to the owner's latest message.\n")
	for _, m := range history {
		who := "Owner"
		if m.Role == "assistant" {
			who = "Advisor (you)"
		}
		fmt.Fprintf(&b, "\n### %s\n\n%s\n", who, strings.TrimSpace(m.Text))
	}
	return b.String()
}
