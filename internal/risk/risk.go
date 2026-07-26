package risk

import (
	"fmt"
	"sort"
	"strconv"
	"time"

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

	checkPortID := func(port int, sev, id, title, desc, rem string) {
		if _, ok := portSet[port]; !ok {
			return
		}
		out = append(out, Finding{
			ID: id + "-" + strconv.Itoa(port) + "-" + ip, Severity: sev, Title: title,
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

	check(2376, SeverityInfo, "docker-api-tls", "Docker API (TLS) port open",
		"Docker API on 2376 uses TLS, but LAN exposure still warrants review of certificates and access control.",
		"Restrict 2376 to trusted hosts; verify client cert auth; avoid exposing the API on the wider LAN.")

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

	check(3306, SeverityHigh, "mysql-open", "MySQL / MariaDB port open",
		"Database ports on the LAN are frequent targets when auth or binding is weak.",
		"Bind to localhost or a management VLAN; require strong auth; firewall the port.")

	check(5432, SeverityHigh, "postgres-open", "PostgreSQL port open",
		"PostgreSQL on the LAN may allow data access if credentials or trust auth are weak.",
		"Bind to localhost; use scram/password auth; restrict with firewall rules.")

	check(1433, SeverityHigh, "mssql-open", "Microsoft SQL Server port open",
		"MSSQL on the LAN is a common lateral-movement and brute-force target.",
		"Restrict to trusted hosts; disable unused SQL Browser exposure; use strong auth.")

	check(1521, SeverityHigh, "oracle-open", "Oracle database listener open",
		"Oracle listeners on the LAN can expose databases when misconfigured.",
		"Restrict listener access; use strong auth; keep the database off general LAN segments.")

	check(135, SeverityHigh, "msrpc-open", "Windows RPC (MSRPC) exposed",
		"MSRPC endpoints are used by remote Windows management and are frequently probed on LANs.",
		"Firewall 135 from untrusted hosts; prefer VPN/admin jump hosts for management.")

	check(111, SeverityMedium, "rpcbind-open", "RPCbind / portmapper exposed",
		"RPCbind can advertise NFS and other Unix RPC services to the LAN.",
		"Disable unused RPC services; firewall 111; prefer NFS over authenticated, restricted mounts.")

	check(139, SeverityMedium, "netbios-open", "NetBIOS session service exposed",
		"Legacy NetBIOS (139) often accompanies SMB and widens the Windows file-sharing attack surface.",
		"Disable NetBIOS where unused; prefer SMB over 445 with signing; restrict with firewall rules.")

	check(9100, SeverityMedium, "printer-open", "Raw printer port (9100) open",
		"Many network printers accept unauthenticated print jobs on TCP 9100.",
		"Place printers on a restricted VLAN; disable unused raw printing; require authenticated print protocols when possible.")

	check(9200, SeverityMedium, "elastic-open", "Elasticsearch HTTP API open",
		"Elasticsearch APIs may allow data access or cluster changes if unsecured.",
		"Enable security features; bind to localhost; put behind authenticated proxy.")

	check(80, SeverityMedium, "http-cleartext", "HTTP (cleartext) service",
		"HTTP admin or device UIs on the LAN may leak credentials or sessions.",
		"Prefer HTTPS; avoid sending credentials over HTTP; restrict admin UIs.")

	for _, port := range []int{8000, 8080, 5000, 8888} {
		checkPortID(port, SeverityMedium, "http-alt", "Cleartext / admin HTTP port open",
			"Alternate HTTP ports often host admin UIs, proxies, or dev services without TLS.",
			"Prefer HTTPS; restrict admin interfaces; close unused alternate HTTP ports.")
	}

	check(25, SeverityMedium, "smtp-open", "SMTP service open",
		"Open SMTP on LAN hosts can be abused for spam relay if misconfigured.",
		"Disable unused SMTP; require auth; restrict relay.")

	if hp.host.IsGateway || hp.host.LikelyRouterGuess {
		for _, port := range []int{23, 445, 3389} {
			if _, ok := portSet[port]; !ok {
				continue
			}
			out = append(out, Finding{
				ID:       "gateway-mgmt-" + strconv.Itoa(port) + "-" + ip,
				Severity: SeverityHigh,
				Title:    "Gateway / router management service exposed",
				Description: fmt.Sprintf(
					"Host %s looks like a gateway/router and has management-related port %d open on the LAN.",
					ip, port,
				),
				Remediation: "Restrict router management to a trusted admin network or VPN; disable WAN/LAN remote admin if unused.",
				HostIP:      ip,
				Port:        port,
			})
		}
	}

	out = append(out, evalEnrichment(ip, hp.ports)...)

	// Identification noise is kept low: skip when hostname, vendor, or probe hints identify the host.
	if hp.host.Hostname == "" && hp.host.Vendor == "" && !hasIdentityHint(hp.ports) {
		out = append(out, Finding{
			ID: "unknown-device-" + ip, Severity: SeverityInfo, Title: "Unidentified device",
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

func hasIdentityHint(ports []scan.OpenPort) bool {
	for _, p := range ports {
		if p.HTTPTitle != "" || p.HTTPServer != "" || p.Banner != "" || p.TLSCommonName != "" {
			return true
		}
	}
	return false
}

func evalEnrichment(ip string, ports []scan.OpenPort) []Finding {
	var out []Finding
	for _, p := range ports {
		if p.TLSExpired {
			out = append(out, Finding{
				ID:       "tls-expired-" + strconv.Itoa(p.Port) + "-" + ip,
				Severity: SeverityMedium,
				Title:    "TLS certificate expired",
				Description: fmt.Sprintf(
					"HTTPS service on %s:%d presents a certificate that expired%s.",
					ip, p.Port, formatNotAfter(p.TLSNotAfter),
				),
				Remediation: "Renew the certificate; prefer a privately trusted or publicly trusted cert for admin UIs.",
				HostIP:      ip,
				Port:        p.Port,
			})
		}
		if p.TLSSelfSigned {
			cn := p.TLSCommonName
			if cn == "" {
				cn = "(no CN)"
			}
			out = append(out, Finding{
				ID:       "tls-self-signed-" + strconv.Itoa(p.Port) + "-" + ip,
				Severity: SeverityInfo,
				Title:    "Self-signed TLS certificate",
				Description: fmt.Sprintf(
					"HTTPS service on %s:%d uses a self-signed certificate (CN %s). Common on LAN gear, but browsers will warn.",
					ip, p.Port, cn,
				),
				Remediation: "Replace with a cert from your internal CA or a public CA if the UI is shared; verify you trust this device.",
				HostIP:      ip,
				Port:        p.Port,
			})
		}
	}
	return out
}

func formatNotAfter(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return " on " + t.UTC().Format("2006-01-02")
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
