package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ValidateLocalURL accepts a plain-HTTP model server on this computer only
// (localhost, 127.0.0.0/8, ::1) and returns its base URL.
func ValidateLocalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("enter the model server as http://127.0.0.1:PORT")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); !(host == "localhost" || ip != nil && ip.IsLoopback()) {
		return "", errors.New("the model server must run on this computer (localhost or 127.0.0.1)")
	}
	switch strings.TrimSuffix(u.Path, "/") {
	case "", "/v1":
	default:
		return "", errors.New("enter only the server address, such as http://127.0.0.1:8080")
	}
	return "http://" + u.Host, nil
}

// localClient connects to loopback addresses only, whatever a name resolves
// to, uses no proxy, and follows no redirects.
var localClient = &http.Client{
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
					return fmt.Errorf("refusing to connect to %s: not this computer", address)
				}
				return nil
			},
		}).DialContext,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func localStatus(ctx context.Context, raw string) Status {
	st := Status{ID: "local", Label: "Local model server", Note: "Keeps what you share on this computer. Works with llama.cpp, Ollama, LM Studio and other OpenAI-compatible servers."}
	if strings.TrimSpace(raw) == "" {
		st.Reason = "Enter the server address."
		return st
	}
	base, err := ValidateLocalURL(raw)
	if err != nil {
		st.Reason = err.Error()
		return st
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := localJSON(ctx, http.MethodGet, base+"/v1/models", nil, &list); err != nil {
		st.Reason = "No model server answered at " + base + "."
		return st
	}
	for _, m := range list.Data {
		st.Models = append(st.Models, m.ID)
	}
	st.Available = true
	return st
}

func askLocal(ctx context.Context, req Request) (string, error) {
	base, err := ValidateLocalURL(req.LocalURL)
	if err != nil {
		return "", err
	}
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	msgs := []msg{{"user", req.Prompt}}
	for _, m := range req.History {
		msgs = append(msgs, msg{m.Role, m.Text})
	}
	body := map[string]any{"messages": msgs, "stream": false}
	if req.LocalModel != "" {
		body["model"] = req.LocalModel
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := localJSON(ctx, http.MethodPost, base+"/v1/chat/completions", body, &out); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("stopped")
		}
		return "", err
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("the model server returned no reply")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func localJSON(ctx context.Context, method, u string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := localClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the model server: %v", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4*outputCap))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("the model server answered %s: %s", res.Status, firstLine(string(data)))
	}
	return json.Unmarshal(data, out)
}
