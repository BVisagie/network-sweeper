// Package enrich adds lightweight post-connect hints to open findings ports.
// Probes are short-timeout, educational only (titles, banners, TLS summary).
package enrich

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BVisagie/network-sweeper/internal/scan"
)

var (
	httpPorts   = map[int]bool{80: true, 8000: true, 8080: true, 5000: true, 8888: true, 9200: true}
	httpsPorts  = map[int]bool{443: true, 8443: true, 993: true, 995: true, 2376: true}
	bannerPorts = map[int]bool{21: true, 22: true, 25: true}
)

// Results enriches open ports in place (and returns the same slice for convenience).
func Results(ctx context.Context, results []scan.Result, timeout time.Duration, concurrency int) []scan.Result {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range results {
		i := i
		for j := range results[i].Ports {
			j := j
			if !needsProbe(results[i].Ports[j].Port) {
				continue
			}
			wg.Add(1)
			ip := results[i].IP
			go func() {
				defer wg.Done()
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				defer func() { <-sem }()
				enrichPort(ctx, ip, &results[i].Ports[j], timeout)
			}()
		}
	}
	wg.Wait()
	return results
}

func needsProbe(port int) bool {
	return httpPorts[port] || httpsPorts[port] || bannerPorts[port]
}

func enrichPort(ctx context.Context, ip string, op *scan.OpenPort, timeout time.Duration) {
	switch {
	case httpsPorts[op.Port]:
		probeTLS(ctx, ip, op, timeout)
		if op.Port == 443 || op.Port == 8443 {
			probeHTTP(ctx, ip, op, timeout, true)
		}
	case httpPorts[op.Port]:
		probeHTTP(ctx, ip, op, timeout, false)
	case bannerPorts[op.Port]:
		probeBanner(ctx, ip, op, timeout)
	}
}

func probeBanner(ctx context.Context, ip string, op *scan.OpenPort, timeout time.Duration) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", op.Port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if n <= 0 {
		_ = err
		return
	}
	op.Banner = sanitizeLine(string(buf[:n]))
}

func probeTLS(ctx context.Context, ip string, op *scan.OpenPort, timeout time.Duration) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", op.Port))
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	cfg := &tls.Config{
		InsecureSkipVerify: true, // LAN inventory probe only; not for trust decisions
		ServerName:         ip,
		MinVersion:         tls.VersionTLS10,
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	op.TLSCommonName = strings.TrimSpace(cert.Subject.CommonName)
	if op.TLSCommonName == "" && len(cert.DNSNames) > 0 {
		op.TLSCommonName = cert.DNSNames[0]
	}
	op.TLSIssuer = strings.TrimSpace(cert.Issuer.CommonName)
	if op.TLSIssuer == "" {
		op.TLSIssuer = cert.Issuer.String()
	}
	op.TLSNotAfter = cert.NotAfter.UTC()
	op.TLSExpired = time.Now().After(cert.NotAfter)
	op.TLSSelfSigned = cert.Issuer.String() == cert.Subject.String()
}

func probeHTTP(ctx context.Context, ip string, op *scan.OpenPort, timeout time.Duration, useTLS bool) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, fmt.Sprintf("%d", op.Port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "NetworkSweeper/1.0 (local inventory)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if op.HTTPServer == "" {
		op.HTTPServer = sanitizeHeader(resp.Header.Get("Server"))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if title := extractTitle(string(body)); title != "" {
		op.HTTPTitle = title
	}
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	gt := strings.Index(html[start:], ">")
	if gt < 0 {
		return ""
	}
	contentStart := start + gt + 1
	endRel := strings.Index(strings.ToLower(html[contentStart:]), "</title>")
	if endRel < 0 {
		return ""
	}
	return sanitizeLine(html[contentStart : contentStart+endRel])
}

func sanitizeHeader(s string) string {
	return sanitizeLine(s)
}

func sanitizeLine(s string) string {
	s = strings.TrimSpace(s)
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
		if b.Len() >= 120 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if !utf8.ValidString(out) {
		return ""
	}
	return out
}

// IdentityHint returns a short human label from enriched ports (title, CN, or banner).
func IdentityHint(ports []scan.OpenPort) string {
	for _, p := range ports {
		if p.HTTPTitle != "" {
			return p.HTTPTitle
		}
	}
	for _, p := range ports {
		if p.TLSCommonName != "" {
			return p.TLSCommonName
		}
	}
	for _, p := range ports {
		if p.HTTPServer != "" {
			return p.HTTPServer
		}
	}
	for _, p := range ports {
		if p.Banner != "" {
			// Prefer a short token from banner lines like "SSH-2.0-OpenSSH_9.0"
			line := p.Banner
			if sc := bufio.NewScanner(strings.NewReader(line)); sc.Scan() {
				line = sc.Text()
			}
			if len(line) > 64 {
				line = line[:64]
			}
			return line
		}
	}
	return ""
}
