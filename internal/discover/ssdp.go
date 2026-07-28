package discover

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const ssdpPort = 1900

var ssdpGroup = net.ParseIP("239.255.255.250")

const ssdpSearch = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: ssdp:all\r\n" +
	"\r\n"

// ProbeSSDP sends a multicast M-SEARCH and attaches UPnP hints only to known hosts.
func ProbeSSDP(ctx context.Context, hosts []Host, window time.Duration) {
	if window <= 0 {
		window = 2500 * time.Millisecond
	}
	byIP := map[string]*Host{}
	for i := range hosts {
		byIP[hosts[i].IP] = &hosts[i]
	}
	if len(byIP) == 0 || ctx.Err() != nil {
		return
	}

	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return
	}
	defer pc.Close()

	deadline := time.Now().Add(window)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = pc.SetDeadline(deadline)

	dst := &net.UDPAddr{IP: ssdpGroup, Port: ssdpPort}
	_, _ = pc.WriteTo([]byte(ssdpSearch), dst)

	buf := make([]byte, 4096)
	seen := map[string]string{} // ip -> LOCATION
	for {
		if ctx.Err() != nil {
			break
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok || ua.IP == nil {
			continue
		}
		ip := ua.IP.To4()
		if ip == nil {
			continue
		}
		ipStr := ip.String()
		h, known := byIP[ipStr]
		if !known {
			continue
		}
		h.UPnP = true
		loc := parseSSDPLocation(string(buf[:n]))
		if loc != "" {
			seen[ipStr] = loc
		}
	}

	client := &http.Client{
		Timeout: 800 * time.Millisecond,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 1 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	for ip, loc := range seen {
		if ctx.Err() != nil {
			return
		}
		h := byIP[ip]
		if h == nil {
			continue
		}
		name := fetchUPnPFriendlyName(ctx, client, loc)
		if name != "" {
			h.UPnPFriendlyName = name
			setHostnameIfEmpty(h, name)
		}
	}
}

func parseSSDPLocation(msg string) string {
	sc := bufio.NewScanner(strings.NewReader(msg))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ':'); i > 0 {
			key := strings.TrimSpace(line[:i])
			if strings.EqualFold(key, "LOCATION") {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func fetchUPnPFriendlyName(ctx context.Context, client *http.Client, location string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "NetworkSweeper/1.0 (local inventory)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ""
	}
	return extractXMLTag(string(body), "friendlyName")
}

func extractXMLTag(xml, tag string) string {
	lower := strings.ToLower(xml)
	open := "<" + strings.ToLower(tag)
	start := strings.Index(lower, open)
	if start < 0 {
		return ""
	}
	gt := strings.Index(xml[start:], ">")
	if gt < 0 {
		return ""
	}
	contentStart := start + gt + 1
	closeTag := "</" + strings.ToLower(tag) + ">"
	endRel := strings.Index(strings.ToLower(xml[contentStart:]), closeTag)
	if endRel < 0 {
		return ""
	}
	return sanitizeHostname(xml[contentStart : contentStart+endRel])
}
