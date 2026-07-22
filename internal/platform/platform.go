package platform

import (
	"runtime"
)

// Capability describes a scan-related capability and its status on this OS.
type Capability struct {
	Name   string `json:"name"`
	Status string `json:"status"` // full | elevated | partial | unavailable | deferred
	Detail string `json:"detail"`
}

// Info is runtime platform information for the Limitations view.
type Info struct {
	OS           string       `json:"os"`
	Arch         string       `json:"arch"`
	Elevated     bool         `json:"elevated"`
	Capabilities []Capability `json:"capabilities"`
	Notes        []string     `json:"notes"`
}

// Snapshot returns current platform capability info.
func Snapshot(elevated bool) Info {
	info := Info{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Elevated: elevated,
		Notes: []string{
			"In unprivileged mode, a host that does not accept connections on any discovery port will not appear at all — not merely with missing MAC/vendor.",
			"Code signing / notarization is deferred for v1; SmartScreen (Windows) and Gatekeeper (macOS) may warn on unsigned binaries.",
			"Wi‑Fi client isolation and other VLANs/guest networks hide peers at the network layer — the app cannot see them.",
		},
	}
	info.Capabilities = []Capability{
		{Name: "IPv4 interface + CIDR detection", Status: "full", Detail: "Works without elevation on all supported OSes."},
		{Name: "TCP connect discovery", Status: "full", Detail: "Primary portable unprivileged discovery path."},
		{Name: "TCP findings port scan", Status: "full", Detail: "Common services labeled for overview and risk heuristics."},
		{Name: "ARP cache MAC enrichment", Status: "full", Detail: "MAC appears after the OS has an ARP entry for the host."},
		{Name: "Active ARP sweep", Status: statusElevated(elevated), Detail: "Requires Admin / CAP_NET_RAW / root for raw L2; optional Deep discovery."},
		icmpCap(elevated),
		{Name: "Hostname (DNS/mDNS/NetBIOS)", Status: "partial", Detail: "Best-effort; many IoT devices advertise little."},
		{Name: "OS / device fingerprint", Status: "partial", Detail: "Port + banner heuristics only in v1."},
		{Name: "SYN / raw half-open scan", Status: "unavailable", Detail: "Deferred in v1 for portability; TCP connect only."},
		{Name: "Hosts behind AP / client isolation", Status: "unavailable", Detail: "Peers are hidden by the access point."},
		{Name: "Other VLANs / guest Wi‑Fi", Status: "unavailable", Detail: "Only attached L2/L3 segments are visible."},
		{Name: "Code signing / notarization", Status: "deferred", Detail: "Post-v1; unsigned builds may trigger OS trust warnings."},
		{Name: "Local API bind beyond localhost", Status: "unavailable", Detail: "v1 binds 127.0.0.1 only."},
	}
	return info
}

func statusElevated(elevated bool) string {
	if elevated {
		return "full"
	}
	return "elevated"
}

func icmpCap(elevated bool) Capability {
	switch runtime.GOOS {
	case "windows":
		return Capability{
			Name:   "ICMP ping discovery",
			Status: "partial",
			Detail: "Windows IP Helper / ping may work without full elevation; used as an extra discovery signal.",
		}
	default:
		st := "elevated"
		if elevated {
			st = "full"
		}
		return Capability{
			Name:   "ICMP ping discovery",
			Status: st,
			Detail: "Linux/macOS raw ICMP typically needs privileges; TCP discovery is used first when unprivileged.",
		}
	}
}
