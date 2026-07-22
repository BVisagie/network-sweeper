package discover

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ReadARPTable returns IP -> MAC from the OS ARP cache.
func ReadARPTable() map[string]string {
	switch runtime.GOOS {
	case "linux":
		return readARPLinux()
	case "darwin":
		return readARPCommand("arp", "-an")
	case "windows":
		return readARPCommand("arp", "-a")
	default:
		return readARPLinux()
	}
}

func readARPLinux() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		if mac == "00:00:00:00:00:00" || mac == "<incomplete>" {
			continue
		}
		out[ip] = strings.ToLower(mac)
	}
	return out
}

func readARPCommand(name string, args ...string) map[string]string {
	out := map[string]string{}
	cmd := exec.Command(name, args...)
	b, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// macOS: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
		// Windows: 192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
		ip := ""
		mac := ""
		if i := strings.Index(line, "("); i >= 0 {
			j := strings.Index(line[i:], ")")
			if j > 1 {
				cand := line[i+1 : i+j]
				if net.ParseIP(cand) != nil {
					ip = cand
				}
			}
		}
		fields := strings.Fields(line)
		if ip == "" && len(fields) > 0 && net.ParseIP(fields[0]) != nil {
			ip = fields[0]
		}
		for _, f := range fields {
			f = strings.ReplaceAll(f, "-", ":")
			if looksLikeMAC(f) {
				mac = strings.ToLower(f)
				break
			}
		}
		if ip != "" && mac != "" && mac != "ff:ff:ff:ff:ff:ff" {
			out[ip] = mac
		}
	}
	return out
}

func looksLikeMAC(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
	}
	return true
}
