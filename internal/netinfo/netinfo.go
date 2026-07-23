package netinfo

import (
	"fmt"
	"net"
	"strings"
)

// InterfaceInfo describes a network interface with IPv4 addresses.
type InterfaceInfo struct {
	Name    string   `json:"name"`
	Index   int      `json:"index"`
	MTU     int      `json:"mtu"`
	Flags   string   `json:"flags"`
	IPv4    []string `json:"ipv4"`
	CIDRs   []string `json:"cidrs"`
	IsUp    bool     `json:"isUp"`
	IsLoop  bool     `json:"isLoopback"`
}

// ListIPv4Interfaces returns non-loopback (and optionally loopback) IPv4 interfaces.
func ListIPv4Interfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:   iface.Name,
			Index:  iface.Index,
			MTU:    iface.MTU,
			Flags:  iface.Flags.String(),
			IsUp:   iface.Flags&net.FlagUp != 0,
			IsLoop: iface.Flags&net.FlagLoopback != 0,
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			info.IPv4 = append(info.IPv4, ipNet.IP.String())
			info.CIDRs = append(info.CIDRs, ipNet.String())
		}
		if len(info.IPv4) == 0 {
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// LocalSubnets returns IPv4 CIDRs for non-loopback, up interfaces.
func LocalSubnets() ([]*net.IPNet, error) {
	ifaces, err := ListIPv4Interfaces()
	if err != nil {
		return nil, err
	}
	var nets []*net.IPNet
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if iface.IsLoop || !iface.IsUp {
			continue
		}
		for _, c := range iface.CIDRs {
			_, ipNet, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			key := ipNet.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			nets = append(nets, ipNet)
		}
	}
	return nets, nil
}

// ParseCIDRList parses comma/space-separated CIDRs.
func ParseCIDRList(s string) ([]*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty CIDR list")
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	})
	var nets []*net.IPNet
	for _, p := range parts {
		_, ipNet, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", p, err)
		}
		if ipNet.IP.To4() == nil {
			return nil, fmt.Errorf("only IPv4 CIDRs supported: %s", p)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// ContainsNet reports whether outer fully contains inner.
func ContainsNet(outer, inner *net.IPNet) bool {
	if outer == nil || inner == nil {
		return false
	}
	onesOuter, bitsOuter := outer.Mask.Size()
	onesInner, bitsInner := inner.Mask.Size()
	if bitsOuter != bitsInner {
		return false
	}
	if onesInner < onesOuter {
		return false
	}
	return outer.Contains(inner.IP)
}

// IPInAny reports whether ip is contained in any of the networks.
func IPInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// RangeAllowed checks whether target CIDRs are within allowed local subnets,
// or customOptIn is true. A target is allowed when it is equal to a local subnet
// or a subset of one (narrower mask inside a local network).
func RangeAllowed(targets, local []*net.IPNet, customOptIn bool) error {
	if customOptIn {
		return nil
	}
	if len(local) == 0 {
		return fmt.Errorf("no local subnets detected; enable custom range opt-in to scan")
	}
	for _, t := range targets {
		ok := false
		for _, l := range local {
			if sameNetwork(l, t) || ContainsNet(l, t) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("target %s is outside detected local subnets; enable custom range opt-in to proceed", t.String())
		}
	}
	return nil
}

func sameNetwork(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	aIP := a.IP.Mask(a.Mask)
	bIP := b.IP.Mask(b.Mask)
	return aIP.Equal(bIP) && a.Mask.String() == b.Mask.String()
}

// HostsInCIDR enumerates usable IPv4 hosts in cidr (skips network/broadcast for masks < 31).
// Caps at maxHosts to avoid huge allocations.
func HostsInCIDR(cidr *net.IPNet, maxHosts int) []net.IP {
	if cidr == nil || cidr.IP.To4() == nil || maxHosts <= 0 {
		return nil
	}
	ip := cidr.IP.Mask(cidr.Mask).To4()
	ones, bits := cidr.Mask.Size()
	usable := CountUsableHosts(cidr)
	base := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	start := uint32(0)
	if ones < 31 && usable > 0 && (1<<uint(bits-ones)) > 2 {
		start = 1
	}
	var hosts []net.IP
	for i := uint32(0); len(hosts) < maxHosts && int(i) < usable; i++ {
		v := base + start + i
		hosts = append(hosts, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
	}
	return hosts
}

// CountUsableHosts returns how many host addresses a CIDR would yield (network/broadcast skipped for masks < 31).
func CountUsableHosts(cidr *net.IPNet) int {
	if cidr == nil || cidr.IP.To4() == nil {
		return 0
	}
	ones, bits := cidr.Mask.Size()
	total := 1 << uint(bits-ones)
	if ones < 31 && total > 2 {
		return total - 2
	}
	return total
}

// LocalIPv4Set returns a set of this machine's non-loopback IPv4 addresses.
func LocalIPv4Set() map[string]bool {
	out := map[string]bool{}
	ifaces, err := ListIPv4Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.IsLoop {
			continue
		}
		for _, ip := range iface.IPv4 {
			out[ip] = true
		}
	}
	return out
}

// LooksLikeCommonRouter reports whether ip is a common home-router host address (.1 or .254).
func LooksLikeCommonRouter(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[3] == 1 || v4[3] == 254
}
