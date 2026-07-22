package risk

import (
	"fmt"
	"sort"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// Severity levels.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is a security exposure signal.
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	HostIP      string `json:"hostIp"`
	Port        int    `json:"port,omitempty"`
}

type hostPorts struct {
	host  discover.Host
	ports []scan.OpenPort
}

// Evaluate builds heuristic findings from hosts and open ports.
func Evaluate(hosts []discover.Host, results []scan.Result) []Finding {
	byIP := map[string][]scan.OpenPort{}
	for _, r := range results {
		byIP[r.IP] = r.Ports
	}
	var findings []Finding
	for _, h := range hosts {
		ports := byIP[h.IP]
		hp := hostPorts{host: h, ports: ports}
		findings = append(findings, evalHost(hp)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	return findings
}

func evalHost(hp hostPorts) []Finding {
	var out []Finding
	ip := hp.host.IP
	portSet := map[int]scan.OpenPort{}
	for _, p := range hp.ports {
		portSet[p.Port] = p
	}

	check := func(port int, sev, id, title, desc, rem string) {
		if _, ok := portSet[port]; !ok {
			return
		}
		out = append(out, Finding{
			ID: id + "-" + ip, Severity: sev, Title: title,
			Description: desc, Remediation: rem, HostIP: ip, Port: port,
		})
	}

	check(23, SeverityCritical, "telnet-open", "Telnet service exposed",
		"Telnet transmits credentials and session data in cleartext.",
		"Disable Telnet and use SSH (port 22) with key-based auth instead.")

	check(21, SeverityHigh, "ftp-open", "FTP service exposed",
		"FTP often allows cleartext authentication and file transfer.",
		"Prefer SFTP/FTPS; disable anonymous FTP; restrict to trusted hosts.")

	check(2375, SeverityCritical, "docker-api", "Unencrypted Docker API exposed",
		"Docker API on 2375 without TLS can allow remote container control.",
		"Bind Docker API to localhost only or enable TLS (2376); never expose on LAN without auth.")

	check(445, SeverityHigh, "smb-open", "SMB file sharing exposed",
		"SMB on the LAN can enable lateral movement if misconfigured or unpatched.",
		"Disable SMBv1; require signing; limit share permissions; patch the host.")

	check(3389, SeverityHigh, "rdp-open", "Remote Desktop (RDP) exposed",
		"RDP is a frequent brute-force and exploit target on local networks.",
		"Restrict RDP to trusted hosts/VPN; enable NLA; use strong accounts or disable if unused.")

	check(5900, SeverityHigh, "vnc-open", "VNC remote desktop exposed",
		"VNC often uses weak or no encryption depending on configuration.",
		"Tunnel VNC over SSH/VPN; require strong passwords; disable if unused.")

	check(6379, SeverityHigh, "redis-open", "Redis exposed without assuming auth",
		"Redis on the network is frequently deployed without authentication.",
		"Bind Redis to localhost; enable requirepass/ACL; firewall the port.")

	check(27017, SeverityHigh, "mongo-open", "MongoDB port open",
		"MongoDB instances are often left without auth on internal networks.",
		"Enable authentication; bind to localhost; restrict with firewall rules.")

	check(9200, SeverityMedium, "elastic-open", "Elasticsearch HTTP API open",
		"Elasticsearch APIs may allow data access or cluster changes if unsecured.",
		"Enable security features; bind to localhost; put behind authenticated proxy.")

	check(80, SeverityMedium, "http-cleartext", "HTTP (cleartext) service",
		"HTTP admin or device UIs on the LAN may leak credentials or sessions.",
		"Prefer HTTPS; avoid sending credentials over HTTP; restrict admin UIs.")

	check(25, SeverityMedium, "smtp-open", "SMTP service open",
		"Open SMTP on LAN hosts can be abused for spam relay if misconfigured.",
		"Disable unused SMTP; require auth; restrict relay.")

	if hp.host.MAC == "" {
		out = append(out, Finding{
			ID: "unknown-mac-" + ip, Severity: SeverityInfo, Title: "MAC address unknown",
			Description: "No ARP cache entry yet for this host; vendor identification is limited.",
			Remediation: "Re-scan after traffic to the host, or use elevated Deep discovery for fuller L2 visibility.",
			HostIP:      ip,
		})
	}
	if hp.host.Hostname == "" && hp.host.Vendor == "" {
		out = append(out, Finding{
			ID: "unknown-device-" + ip, Severity: SeverityLow, Title: "Unidentified device",
			Description: fmt.Sprintf("Host %s has no hostname and no known vendor OUI.", ip),
			Remediation: "Verify whether this device is expected on your network; assign a hostname if it is yours.",
			HostIP:      ip,
		})
	}
	if len(hp.ports) >= 8 {
		out = append(out, Finding{
			ID: "wide-open-" + ip, Severity: SeverityMedium, Title: "Wide-open port profile",
			Description: fmt.Sprintf("Host %s has %d open services from the findings list — review exposure.", ip, len(hp.ports)),
			Remediation: "Close unused services; firewall management ports to trusted hosts only.",
			HostIP:      ip,
		})
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}
