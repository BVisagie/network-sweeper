package netinfo

import (
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var (
	reIPv4          = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDarwinGateway = regexp.MustCompile(`(?m)^\s*gateway:\s+(\S+)`)
	reLinuxVia      = regexp.MustCompile(`(?m)^default\s+via\s+(\S+)`)
	reWinGateway    = regexp.MustCompile(`(?i)Default Gateway[^\d]*((?:\d{1,3}\.){3}\d{1,3})`)
)

// DefaultGatewayIPv4 best-effort reads the OS default IPv4 gateway.
// Returns empty string when unavailable.
func DefaultGatewayIPv4() string {
	switch runtime.GOOS {
	case "darwin":
		return parseGatewayOutput(runQuiet("route", "-n", "get", "default"), reDarwinGateway)
	case "linux":
		if g := parseGatewayOutput(runQuiet("ip", "route", "show", "default"), reLinuxVia); g != "" {
			return g
		}
		return parseGatewayOutput(runQuiet("ip", "route"), reLinuxVia)
	case "windows":
		return parseGatewayOutput(runQuiet("route", "print", "0.0.0.0"), reWinGateway)
	default:
		return ""
	}
}

func runQuiet(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(b)
}

func parseGatewayOutput(out string, re *regexp.Regexp) string {
	if out == "" {
		return ""
	}
	if m := re.FindStringSubmatch(out); len(m) > 1 {
		ip := strings.TrimSpace(m[1])
		if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil {
			return ip
		}
	}
	// Fallback: first private-looking IPv4 in output after "gateway"/"via"/"default".
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "gateway") && !strings.Contains(lower, "default") && !strings.Contains(lower, " via ") {
		return ""
	}
	for _, cand := range reIPv4.FindAllString(out, -1) {
		ip := net.ParseIP(cand)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		return cand
	}
	return ""
}

// ParseGatewaySample is exported for tests.
func ParseGatewaySample(osName, sample string) string {
	switch osName {
	case "darwin":
		return parseGatewayOutput(sample, reDarwinGateway)
	case "linux":
		return parseGatewayOutput(sample, reLinuxVia)
	case "windows":
		return parseGatewayOutput(sample, reWinGateway)
	default:
		return ""
	}
}
