package discover

import (
	"bufio"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// arpEntry is one resolved row of the OS ARP cache.
type arpEntry struct {
	MAC string
	// Static is set for permanent/static rows. The OS uses them without
	// asking the network, so they prove nothing about whether the host is up.
	Static bool
}

// ReadARPTable returns IP -> MAC from the OS ARP cache.
func ReadARPTable() map[string]string {
	out := map[string]string{}
	for ip, e := range readARPEntries() {
		out[ip] = e.MAC
	}
	return out
}

func readARPEntries() map[string]arpEntry {
	switch runtime.GOOS {
	case "darwin":
		return readARPCommand("arp", "-an")
	case "windows":
		return readARPCommand("arp", "-a")
	default:
		return readARPLinux()
	}
}

func readARPLinux() map[string]arpEntry {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]arpEntry{}
	}
	defer f.Close()
	return parseProcARP(f)
}

// parseProcARP reads /proc/net/arp content, keeping only complete entries.
func parseProcARP(r io.Reader) map[string]arpEntry {
	out := map[string]arpEntry{}
	sc := bufio.NewScanner(r)
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
		// Flags 0x2 (ATF_COM): complete, the MAC is known. 0x4 (ATF_PERM): static.
		flags, err := strconv.ParseUint(fields[2], 0, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		if mac == "00:00:00:00:00:00" || mac == "<incomplete>" {
			continue
		}
		out[ip] = arpEntry{MAC: strings.ToLower(mac), Static: flags&0x4 != 0}
	}
	return out
}

func readARPCommand(name string, args ...string) map[string]arpEntry {
	b, err := exec.Command(name, args...).Output()
	if err != nil {
		return map[string]arpEntry{}
	}
	return parseARPCommand(string(b))
}

// parseARPCommand reads `arp -an` (macOS) or `arp -a` (Windows) output.
func parseARPCommand(text string) map[string]arpEntry {
	out := map[string]arpEntry{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// macOS: ? (192.168.1.1) at a4:5e:60:e8:1:2d on en0 ifscope [ethernet]
		//        (bytes lose their leading zero; static rows say "permanent")
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
		static := false
		for _, f := range fields {
			switch strings.ToLower(f) {
			case "permanent", "static":
				static = true
			}
			if mac == "" {
				mac = normalizeMAC(strings.ReplaceAll(f, "-", ":"))
			}
		}
		if ip != "" && mac != "" && mac != "ff:ff:ff:ff:ff:ff" {
			out[ip] = arpEntry{MAC: mac, Static: static}
		}
	}
	return out
}

// normalizeMAC returns s as six lowercase two-digit hex bytes, padding the
// single-digit bytes macOS prints, or "" when s is not a MAC.
func normalizeMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return ""
		}
		if _, err := strconv.ParseUint(p, 16, 8); err != nil {
			return ""
		}
		if len(p) == 1 {
			p = "0" + p
		}
		parts[i] = strings.ToLower(p)
	}
	return strings.Join(parts, ":")
}

// unicastMAC reports whether mac is a usable unicast hardware address: not
// broadcast, not multicast (01:00:5e…, 33:33…), and not all zeros.
func unicastMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	if hw[0]&0x01 != 0 {
		return false
	}
	for _, b := range hw {
		if b != 0 {
			return true
		}
	}
	return false
}
