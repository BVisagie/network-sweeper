package platform

import (
	"runtime"

	"github.com/BVisagie/network-sweeper/internal/discover"
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
// Statuses must match implemented behavior: never mark unimplemented features as full when elevated.
func Snapshot(elevated bool) Info {
	info := Info{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Elevated: elevated,
		Notes: []string{
			"In unprivileged mode, a host that does not accept connections on any discovery port (and is not found via ICMP/ARP when Deep discovery is available) will not appear at all — not merely with missing MAC/vendor.",
			"Deep discovery adds ICMP (system ping) and, on Linux/macOS when elevated, an active ARP sweep. On Windows, ping may already run as a boost without Deep/Admin; active ARP remains deferred.",
			"Code signing / notarization is deferred for v1; SmartScreen (Windows) and Gatekeeper (macOS) may warn on unsigned binaries.",
			"Wi‑Fi client isolation and other VLANs/guest networks hide peers at the network layer — the app cannot see them.",
			"Elevation: Windows — Run as administrator. macOS/Linux — run with sudo.",
		},
	}
	info.Capabilities = []Capability{
		{Name: "IPv4 interface + CIDR detection", Status: "full", Detail: "Works without elevation on all supported OSes."},
		{Name: "TCP connect discovery", Status: "full", Detail: "Primary portable unprivileged discovery path."},
		{Name: "TCP findings port scan", Status: "full", Detail: "Common services labeled for overview and risk heuristics."},
		{Name: "ARP cache MAC enrichment", Status: "full", Detail: "MAC appears after the OS has an ARP entry for the host."},
		arpSweepCap(elevated),
		icmpCap(elevated),
		{Name: "Hostname resolution", Status: "partial", Detail: "Reverse DNS, then NetBIOS (UDP/137), then mDNS reverse PTR; SSDP/SNMP may fill remaining empty names. Not exhaustive on all IoT."},
		{Name: "Device identification", Status: "partial", Detail: "Port labels, offline OUI, hostname hints, HTTP/TLS/banner probes, SSDP friendlyName, SNMP sysDescr — not OS fingerprinting."},
		{Name: "Service enrichment (HTTP/TLS/banners)", Status: "full", Detail: "Lightweight post-connect probes on open findings ports; educational hints only."},
		{Name: "SSDP/UPnP inventory hints", Status: "full", Detail: "Multicast M-SEARCH; attaches friendlyName only to already-discovered hosts; educational UPnP finding."},
		{Name: "SNMP soft probe (public)", Status: "full", Detail: "Single community \"public\" GET for sysName/sysDescr; educational finding if it answers — no brute force."},
		{Name: "SYN / raw half-open scan", Status: "unavailable", Detail: "Not available; TCP connect only."},
		{Name: "Hosts behind AP / client isolation", Status: "unavailable", Detail: "Peers are hidden by the access point."},
		{Name: "Other VLANs / guest Wi‑Fi", Status: "unavailable", Detail: "Only attached L2/L3 segments are visible."},
		{Name: "Code signing / notarization", Status: "deferred", Detail: "Post-v1; unsigned builds may trigger OS trust warnings."},
		{Name: "Local API bind beyond localhost", Status: "unavailable", Detail: "Binds 127.0.0.1 only."},
	}
	return info
}

func arpSweepCap(elevated bool) Capability {
	if !discover.ARPSweepSupported() {
		return Capability{
			Name:   "Active ARP sweep",
			Status: "deferred",
			Detail: "Not implemented on this OS (Windows needs Npcap-class support). Deep discovery uses ICMP only here.",
		}
	}
	st := "elevated"
	detail := "Deep discovery + elevation sends ARP who-has on local interfaces to find quiet hosts."
	if elevated {
		st = "full"
		detail = "Available with current elevation: ARP who-has during Deep discovery."
	}
	return Capability{Name: "Active ARP sweep", Status: st, Detail: detail}
}

func icmpCap(elevated bool) Capability {
	switch runtime.GOOS {
	case "windows":
		return Capability{
			Name:   "ICMP ping discovery (Deep)",
			Status: "partial",
			Detail: "System ping is attempted as an extra discovery signal even without Admin (and even when Deep is unchecked). Elevation still helps for quieter devices.",
		}
	default:
		st := "elevated"
		if elevated {
			st = "full"
		}
		return Capability{
			Name:   "ICMP ping discovery (Deep)",
			Status: st,
			Detail: "Deep discovery runs system ping (typically needs root/Admin on Linux/macOS). TCP discovery is used first when unprivileged.",
		}
	}
}
