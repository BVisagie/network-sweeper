package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BVisagie/network-sweeper/internal/version"
)

// Result of an opt-in update check.
type Result struct {
	CheckedAt   time.Time `json:"checkedAt"`
	Current     string    `json:"current"`
	Latest      string    `json:"latest,omitempty"`
	UpdateAvailable bool  `json:"updateAvailable"`
	ReleaseURL  string    `json:"releaseUrl,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// CheckLatest queries GitHub Releases for the newest tag. Caller must only
// invoke this when the user has opted in.
func CheckLatest(ctx context.Context, client *http.Client) Result {
	res := Result{CheckedAt: time.Now().UTC(), Current: version.Canonical()}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", version.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "network-sweeper/"+version.Canonical())
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("GitHub API status %d", resp.StatusCode)
		return res
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		res.Error = err.Error()
		return res
	}
	res.Latest = strings.TrimPrefix(rel.TagName, "v")
	res.ReleaseURL = rel.HTMLURL
	res.UpdateAvailable = newer(res.Latest, res.Current)
	return res
}

func stripDev(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimSuffix(v, "-dev")
	return v
}

// newer reports whether latest looks greater than current (simple dotted compare).
func newer(latest, current string) bool {
	lp := splitVer(stripDev(latest))
	cp := splitVer(stripDev(current))
	for i := 0; i < 3; i++ {
		var a, b int
		if i < len(lp) {
			a = lp[i]
		}
		if i < len(cp) {
			b = cp[i]
		}
		if a > b {
			return true
		}
		if a < b {
			return false
		}
	}
	return false
}

func splitVer(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}
