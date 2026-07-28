package discover

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func sanitizeHostname(s string) string {
	s = strings.TrimSpace(s)
	s = decodeBasicEntities(s)
	s = strings.TrimRight(s, ".")
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' {
			break
		}
		if r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if r < 32 || !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 63 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" || !utf8.ValidString(out) {
		return ""
	}
	return out
}

func decodeBasicEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	s = strings.NewReplacer(
		"&quot;", `"`,
		"&#34;", `"`,
		"&#39;", `'`,
		"&apos;", `'`,
		"&lt;", "<",
		"&gt;", ">",
		"&nbsp;", " ",
	).Replace(s)
	return strings.ReplaceAll(s, "&amp;", "&")
}

func setHostnameIfEmpty(h *Host, name string) {
	if h == nil || h.Hostname != "" {
		return
	}
	if n := sanitizeHostname(name); n != "" {
		h.Hostname = n
	}
}
