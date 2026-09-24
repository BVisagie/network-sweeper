package risk

import (
	"fmt"
	"net"
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

// Categories say what kind of statement a finding makes.
const (
	// CategoryObservation: a service or trait was seen; nothing suggests a problem.
	CategoryObservation = "observation"
	// CategoryExposure: something worth reviewing is reachable, but no response
	// showed that it is misconfigured.
	CategoryExposure = "exposure"
	// CategoryIssue: a response showed the configuration concern itself.
	CategoryIssue = "issue"
)

// Confidence says how the finding is supported, separately from severity.
const (
	// ConfidenceConfirmed: a protocol response backs the finding.
	ConfidenceConfirmed = "confirmed"
	// ConfidenceInferred: only an open port (or port count) backs it.
	ConfidenceInferred = "inferred"
)

// Finding is one reviewable statement about a host, with the evidence behind it.
type Finding struct {
	ID          string     `json:"id"`
	Rule        string     `json:"rule"`
	Severity    string     `json:"severity"`
	Category    string     `json:"category"`
	Confidence  string     `json:"confidence"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation"`
	Unknown     string     `json:"unknown,omitempty"` // what the scan could not establish
	Evidence    []Evidence `json:"evidence"`
	HostIP      string     `json:"hostIp"`
	Port        int        `json:"port,omitempty"`
}

// Key identifies the condition on a device across scans: rule plus port.
func (f Finding) Key() string {
	return f.Rule + "/" + strconv.Itoa(f.Port)
}

// Evidence is one observation behind a finding.
type Evidence struct {
	Method     string    `json:"method"` // tcp-connect | http | tls | banner | docker-api | ssdp | snmp | inventory
	Summary    string    `json:"summary"`
	Endpoint   string    `json:"endpoint,omitempty"`
	ObservedAt time.Time `json:"observedAt,omitzero"`
}

// portRule describes the finding for one conventional port. When protocol is
// set and a probe confirmed it, the confirmed fields apply instead.
type portRule struct {
	port        int
	rule        string
	multiPort   bool // ID carries the port (several ports share the rule)
	severity    string
	category    string
	title       string
	description string
	remediation string
	unknown     string

	protocol          string
	confirmedSeverity string
	confirmedCategory string
	confirmedTitle    string
	confirmedDesc     string
	confirmedUnknown  string
	gatewayManagement bool // stronger finding when the host is the gateway
}

const unknownPortOnly = "Only the TCP port answered. The software behind it, its version, and whether it asks for a login were not checked."

var portRules = []portRule{
	{
		port: 23, rule: "telnet-open", severity: SeverityMedium, category: CategoryExposure,
		title:       "Telnet port open",
		description: "Port 23 is conventionally Telnet, which sends logins and sessions in cleartext.",
		remediation: "Disable Telnet and use SSH (port 22) with key-based auth instead.",
		unknown:     unknownPortOnly,
		protocol:    "Telnet", confirmedSeverity: SeverityHigh, confirmedCategory: CategoryIssue,
		confirmedTitle:    "Telnet login service answering",
		confirmedDesc:     "The device answered as a Telnet server, so logins and sessions to it travel in cleartext.",
		confirmedUnknown:  "Whether logins are limited to trusted hosts, and how strong the accounts are.",
		gatewayManagement: true,
	},
	{
		port: 21, rule: "ftp-open", severity: SeverityLow, category: CategoryExposure,
		title:       "FTP port open",
		description: "Port 21 is conventionally FTP, which often authenticates in cleartext.",
		remediation: "Prefer SFTP/FTPS; disable anonymous FTP; restrict to trusted hosts.",
		unknown:     unknownPortOnly,
		protocol:    "FTP", confirmedSeverity: SeverityMedium, confirmedCategory: CategoryIssue,
		confirmedTitle:   "FTP server answering",
		confirmedDesc:    "The device greeted as an FTP server. Plain FTP sends passwords and files in cleartext.",
		confirmedUnknown: "Whether anonymous login is allowed and whether FTPS is offered were not checked.",
	},
	{
		port: 2375, rule: "docker-api", severity: SeverityMedium, category: CategoryExposure,
		title:       "Plaintext Docker API port open",
		description: "Port 2375 is Docker's unencrypted Engine API port. If it is the Docker API, anyone on the LAN could control containers.",
		remediation: "Bind the Docker API to localhost or a Unix socket, or require TLS client certificates (2376).",
		unknown:     unknownPortOnly,
		protocol:    "Docker API", confirmedSeverity: SeverityCritical, confirmedCategory: CategoryIssue,
		confirmedTitle:   "Docker API answering without authentication",
		confirmedDesc:    "The Docker Engine API answered a version request without credentials. Anyone on the LAN can run containers on this host.",
		confirmedUnknown: "Nothing beyond the version call was tried.",
	},
	{
		port: 2376, rule: "docker-api-tls", severity: SeverityInfo, category: CategoryObservation,
		title:       "Docker API (TLS) port open",
		description: "Port 2376 is Docker's TLS Engine API port.",
		remediation: "Restrict 2376 to trusted hosts and confirm client certificate authentication is required.",
		unknown:     "Whether client certificates are required was not checked.",
	},
	{
		port: 445, rule: "smb-open", severity: SeverityLow, category: CategoryExposure,
		title:             "SMB file sharing port open",
		description:       "Port 445 is Windows/Samba file sharing. Normal for NAS boxes and PCs that share folders.",
		remediation:       "Disable SMBv1; require signing; limit share permissions; patch the host.",
		unknown:           "Share permissions, SMB version, and signing were not checked.",
		gatewayManagement: true,
	},
	{
		port: 3389, rule: "rdp-open", severity: SeverityLow, category: CategoryExposure,
		title:             "Remote Desktop (RDP) port open",
		description:       "Port 3389 is Windows Remote Desktop, which gives full control of the machine to anyone who can log in.",
		remediation:       "Restrict RDP to trusted hosts/VPN; enable NLA; use strong accounts or disable if unused.",
		unknown:           "Whether Network Level Authentication is on and how strong the accounts are were not checked.",
		gatewayManagement: true,
	},
	{
		port: 5900, rule: "vnc-open", severity: SeverityLow, category: CategoryExposure,
		title:       "VNC screen sharing port open",
		description: "Port 5900 is VNC, which may use weak or no encryption depending on configuration.",
		remediation: "Tunnel VNC over SSH/VPN; require strong passwords; disable if unused.",
		unknown:     "Whether a password or encryption is required was not checked.",
	},
	{
		port: 6379, rule: "redis-open", severity: SeverityLow, category: CategoryExposure,
		title:       "Redis port open",
		description: "Redis on the network is often deployed without authentication.",
		remediation: "Bind Redis to localhost; enable requirepass/ACL; firewall the port.",
		unknown:     "Whether Redis requires authentication was not checked.",
	},
	{
		port: 27017, rule: "mongo-open", severity: SeverityLow, category: CategoryExposure,
		title:       "MongoDB port open",
		description: "MongoDB instances are sometimes left without auth on internal networks.",
		remediation: "Enable authentication; bind to localhost; restrict with firewall rules.",
		unknown:     "Whether MongoDB requires authentication was not checked.",
	},
	{
		port: 3306, rule: "mysql-open", severity: SeverityLow, category: CategoryExposure,
		title:       "MySQL / MariaDB port open",
		description: "A database reachable from the whole LAN is worth confirming as intended.",
		remediation: "Bind to localhost or a management VLAN; require strong auth; firewall the port.",
		unknown:     "Accounts and which hosts may connect were not checked.",
	},
	{
		port: 5432, rule: "postgres-open", severity: SeverityLow, category: CategoryExposure,
		title:       "PostgreSQL port open",
		description: "A database reachable from the whole LAN is worth confirming as intended.",
		remediation: "Bind to localhost; use scram/password auth; restrict with firewall rules.",
		unknown:     "Authentication settings (pg_hba.conf) were not checked.",
	},
	{
		port: 1433, rule: "mssql-open", severity: SeverityLow, category: CategoryExposure,
		title:       "Microsoft SQL Server port open",
		description: "A database reachable from the whole LAN is worth confirming as intended.",
		remediation: "Restrict to trusted hosts; disable unused SQL Browser exposure; use strong auth.",
		unknown:     "Accounts and which hosts may connect were not checked.",
	},
	{
		port: 1521, rule: "oracle-open", severity: SeverityLow, category: CategoryExposure,
		title:       "Oracle database listener open",
		description: "A database listener reachable from the whole LAN is worth confirming as intended.",
		remediation: "Restrict listener access; use strong auth; keep the database off general LAN segments.",
		unknown:     "Listener and account settings were not checked.",
	},
	{
		port: 9200, rule: "elastic-open", severity: SeverityLow, category: CategoryExposure,
		title:       "Elasticsearch port open",
		description: "Elasticsearch APIs may allow data access or cluster changes if security features are off.",
		remediation: "Enable security features; bind to localhost; put behind authenticated proxy.",
		unknown:     "Whether the API requires credentials was not checked.",
	},
	{
		port: 135, rule: "msrpc-open", severity: SeverityInfo, category: CategoryObservation,
		title:       "Windows RPC (MSRPC) port open",
		description: "Normal on Windows machines; used by remote management tools.",
		remediation: "Firewall 135 from untrusted hosts; prefer VPN/admin jump hosts for management.",
	},
	{
		port: 111, rule: "rpcbind-open", severity: SeverityInfo, category: CategoryObservation,
		title:       "RPCbind / portmapper open",
		description: "RPCbind advertises NFS and other Unix RPC services to the LAN.",
		remediation: "Disable unused RPC services; firewall 111; prefer NFS over authenticated, restricted mounts.",
	},
	{
		port: 139, rule: "netbios-open", severity: SeverityInfo, category: CategoryObservation,
		title:       "NetBIOS session port open",
		description: "Legacy NetBIOS file sharing, often alongside SMB.",
		remediation: "Disable NetBIOS where unused; prefer SMB over 445 with signing; restrict with firewall rules.",
	},
	{
		port: 9100, rule: "printer-open", severity: SeverityInfo, category: CategoryObservation,
		title:       "Raw printer port (9100) open",
		description: "Many network printers accept print jobs on TCP 9100 without a login.",
		remediation: "Place printers on a restricted VLAN; disable unused raw printing; require authenticated print protocols when possible.",
	},
	{
		port: 80, rule: "http-cleartext", severity: SeverityInfo, category: CategoryObservation,
		title:       "HTTP (cleartext) port open",
		description: "Web pages on port 80 are not encrypted. Avoid logging in to admin pages over it.",
		remediation: "Prefer HTTPS; avoid sending credentials over HTTP; restrict admin UIs.",
		unknown:     unknownPortOnly,
		protocol:    "HTTP", confirmedSeverity: SeverityInfo, confirmedCategory: CategoryObservation,
		confirmedTitle: "Cleartext web page (HTTP)",
		confirmedDesc:  "The device served a web page over unencrypted HTTP. Avoid logging in to admin pages over it.",
	},
	{
		port: 25, rule: "smtp-open", severity: SeverityInfo, category: CategoryObservation,
		title:       "SMTP port open",
		description: "Mail servers accept messages here. Relaying for anyone is the concern, and it was not tested.",
		remediation: "Disable unused SMTP; require auth; restrict relay.",
		unknown:     "Whether the server relays mail for unauthenticated senders was not tested.",
		protocol:    "SMTP", confirmedSeverity: SeverityInfo, confirmedCategory: CategoryObservation,
		confirmedTitle:   "SMTP server answering",
		confirmedDesc:    "The device greeted as a mail server.",
		confirmedUnknown: "Whether the server relays mail for unauthenticated senders was not tested.",
	},
}

func init() {
	for _, port := range []int{8000, 8080, 5000, 8888} {
		portRules = append(portRules, portRule{
			port: port, rule: "http-alt", multiPort: true, severity: SeverityInfo, category: CategoryObservation,
			title:       "Alternate HTTP port open",
			description: "Alternate HTTP ports often host admin UIs, proxies, or dev services without TLS.",
			remediation: "Prefer HTTPS; restrict admin interfaces; close unused alternate HTTP ports.",
			unknown:     unknownPortOnly,
			protocol:    "HTTP", confirmedSeverity: SeverityInfo, confirmedCategory: CategoryObservation,
			confirmedTitle: "Cleartext web service on an alternate port",
			confirmedDesc:  "The device served HTTP on an alternate port, usually an admin UI, proxy, or dev service.",
		})
	}
}

// Evaluate builds findings from hosts and open ports, stamped with now.
func Evaluate(hosts []discover.Host, results []scan.Result) []Finding {
	return EvaluateAt(hosts, results, time.Now().UTC())
}

// EvaluateAt is Evaluate with an explicit observation time.
func EvaluateAt(hosts []discover.Host, results []scan.Result, at time.Time) []Finding {
	byIP := map[string][]scan.OpenPort{}
	for _, r := range results {
		byIP[r.IP] = r.Ports
	}
	var findings []Finding
	for _, h := range hosts {
		findings = append(findings, evalHost(h, byIP[h.IP], at)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return SeverityRank(findings[i].Severity) < SeverityRank(findings[j].Severity)
	})
	return findings
}

func evalHost(h discover.Host, ports []scan.OpenPort, at time.Time) []Finding {
	var out []Finding
	ip := h.IP
	portSet := map[int]scan.OpenPort{}
	for _, p := range ports {
		portSet[p.Port] = p
	}
	isGateway := h.IsGateway || h.LikelyRouterGuess

	for _, r := range portRules {
		op, ok := portSet[r.port]
		if !ok {
			continue
		}
		out = append(out, portFinding(r, ip, op, isGateway, at))
	}

	out = append(out, evalEnrichment(ip, ports, at)...)

	if h.UPnP {
		desc := fmt.Sprintf("Host %s answered an SSDP/UPnP discovery on the LAN.", ip)
		summary := "Answered SSDP M-SEARCH"
		if h.UPnPFriendlyName != "" {
			desc = fmt.Sprintf("Host %s answered SSDP/UPnP discovery (friendly name %q).", ip, h.UPnPFriendlyName)
			summary += fmt.Sprintf("; friendly name %q", h.UPnPFriendlyName)
		}
		out = append(out, Finding{
			ID: "upnp-ssdp-" + ip, Rule: "upnp-ssdp", Severity: SeverityInfo,
			Category: CategoryObservation, Confidence: ConfidenceConfirmed,
			Title:       "UPnP/SSDP responder on LAN",
			Description: desc,
			Remediation: "Disable UPnP if unused; keep firmware updated; restrict UPnP to trusted segments when possible.",
			Unknown:     "Whether the device lets LAN clients open router ports (IGD port mapping) was not checked.",
			Evidence:    []Evidence{{Method: "ssdp", Summary: summary, Endpoint: net.JoinHostPort(ip, "1900"), ObservedAt: at}},
			HostIP:      ip,
		})
	}
	if h.SNMPPublic {
		desc := fmt.Sprintf("Host %s answered SNMP with the default community string \"public\".", ip)
		summary := `Answered an SNMPv2c GET with community "public"`
		if h.SNMPSysDescr != "" {
			desc = fmt.Sprintf("Host %s answered SNMP community \"public\" (%s).", ip, h.SNMPSysDescr)
			summary += fmt.Sprintf("; sysDescr %q", h.SNMPSysDescr)
		}
		out = append(out, Finding{
			ID: "snmp-public-" + ip, Rule: "snmp-public", Severity: SeverityMedium,
			Category: CategoryIssue, Confidence: ConfidenceConfirmed,
			Title:       "SNMP reachable with public community",
			Description: desc,
			Remediation: "Change or disable the default SNMP community; restrict UDP/161 to management hosts; prefer SNMPv3 with auth.",
			Unknown:     "Whether the community also allows writes was not tested.",
			Evidence:    []Evidence{{Method: "snmp", Summary: summary, Endpoint: net.JoinHostPort(ip, "161"), ObservedAt: at}},
			HostIP:      ip,
			Port:        161,
		})
	}

	// Identification noise is kept low: skip when hostname, vendor, UPnP name, or probe hints identify the host.
	if h.Hostname == "" && h.Vendor == "" && h.UPnPFriendlyName == "" && !hasIdentityHint(ports) {
		out = append(out, Finding{
			ID: "unknown-device-" + ip, Rule: "unknown-device", Severity: SeverityInfo,
			Category: CategoryObservation, Confidence: ConfidenceConfirmed,
			Title:       "Unidentified device",
			Description: fmt.Sprintf("Host %s has no hostname and no known vendor OUI.", ip),
			Remediation: "Verify whether this device is expected on your network; assign a hostname if it is yours.",
			Unknown:     "What the device is. Name lookups and service probes returned nothing identifying.",
			Evidence:    []Evidence{{Method: "inventory", Summary: "No hostname, vendor, UPnP name, or service hint", Endpoint: ip, ObservedAt: at}},
			HostIP:      ip,
		})
	}
	if len(ports) >= 8 {
		out = append(out, Finding{
			ID: "wide-open-" + ip, Rule: "wide-open", Severity: SeverityLow,
			Category: CategoryExposure, Confidence: ConfidenceInferred,
			Title:       "Many services open",
			Description: fmt.Sprintf("Host %s has %d open services from the findings list — review which are needed.", ip, len(ports)),
			Remediation: "Close unused services; firewall management ports to trusted hosts only.",
			Unknown:     "Which of these services are intended.",
			Evidence:    []Evidence{{Method: "tcp-connect", Summary: fmt.Sprintf("%d findings ports accepted connections", len(ports)), Endpoint: ip, ObservedAt: at}},
			HostIP:      ip,
		})
	}
	return out
}

// portFinding builds the finding for one open port. A confirmed protocol swaps
// in the confirmed wording and severity; on a gateway, management ports get one
// gateway finding instead of the generic one, so the condition is reported once.
func portFinding(r portRule, ip string, op scan.OpenPort, isGateway bool, at time.Time) Finding {
	endpoint := net.JoinHostPort(ip, strconv.Itoa(op.Port))
	f := Finding{
		ID: r.rule + "-" + ip, Rule: r.rule,
		Severity: r.severity, Category: r.category, Confidence: ConfidenceInferred,
		Title: r.title, Description: r.description, Remediation: r.remediation, Unknown: r.unknown,
		Evidence: []Evidence{{Method: "tcp-connect", Summary: fmt.Sprintf("TCP port %d accepted a connection", op.Port), Endpoint: endpoint, ObservedAt: at}},
		HostIP:   ip, Port: op.Port,
	}
	if r.multiPort {
		f.ID = r.rule + "-" + strconv.Itoa(op.Port) + "-" + ip
	}
	if r.protocol != "" && op.Protocol == r.protocol {
		f.Severity, f.Category, f.Confidence = r.confirmedSeverity, r.confirmedCategory, ConfidenceConfirmed
		f.Title, f.Description, f.Unknown = r.confirmedTitle, r.confirmedDesc, r.confirmedUnknown
		f.Evidence = append(f.Evidence, Evidence{Method: probeMethod(op), Summary: responseSummary(op), Endpoint: endpoint, ObservedAt: at})
	} else if op.Probe == "no-answer" {
		f.Unknown = joinSentences(f.Unknown, "A protocol probe got no recognizable answer, so the service may not be what the port suggests.")
	} else if op.Protocol != "" {
		f.Evidence = append(f.Evidence, Evidence{Method: probeMethod(op), Summary: responseSummary(op), Endpoint: endpoint, ObservedAt: at})
	}
	if isGateway && r.gatewayManagement {
		f.ID = "gateway-mgmt-" + strconv.Itoa(op.Port) + "-" + ip
		f.Rule = "gateway-mgmt"
		f.Severity = raise(f.Severity)
		f.Title = "Gateway / router: " + f.Title
		f.Description = fmt.Sprintf("Host %s looks like the gateway/router. ", ip) + f.Description
		f.Remediation = "Restrict router management to a trusted admin network or VPN; disable remote admin services you do not use. " + f.Remediation
	}
	return f
}

// raise lifts a severity one step, to at least medium and at most high.
func raise(sev string) string {
	switch sev {
	case SeverityCritical, SeverityHigh, SeverityMedium:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

func probeMethod(op scan.OpenPort) string {
	switch op.Protocol {
	case "HTTP", "HTTPS":
		return "http"
	case "TLS":
		return "tls"
	case "Docker API":
		return "docker-api"
	default:
		return "banner"
	}
}

func responseSummary(op scan.OpenPort) string {
	switch {
	case op.Protocol == "Docker API":
		return "GET /version returned Docker Engine version data"
	case op.Banner != "":
		return fmt.Sprintf("%s greeting: %q", op.Protocol, op.Banner)
	case op.Protocol == "Telnet":
		return "Telnet option negotiation received"
	case op.HTTPTitle != "":
		return fmt.Sprintf("%s response, page title %q", op.Protocol, op.HTTPTitle)
	case op.HTTPServer != "":
		return fmt.Sprintf("%s response, Server %q", op.Protocol, op.HTTPServer)
	default:
		return op.Protocol + " response received"
	}
}

func joinSentences(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

func hasIdentityHint(ports []scan.OpenPort) bool {
	for _, p := range ports {
		if p.HTTPTitle != "" || p.HTTPServer != "" || p.Banner != "" || p.TLSCommonName != "" {
			return true
		}
	}
	return false
}

func evalEnrichment(ip string, ports []scan.OpenPort, at time.Time) []Finding {
	var out []Finding
	for _, p := range ports {
		endpoint := net.JoinHostPort(ip, strconv.Itoa(p.Port))
		if p.TLSExpired {
			out = append(out, Finding{
				ID:         "tls-expired-" + strconv.Itoa(p.Port) + "-" + ip,
				Rule:       "tls-expired",
				Severity:   SeverityMedium,
				Category:   CategoryIssue,
				Confidence: ConfidenceConfirmed,
				Title:      "TLS certificate expired",
				Description: fmt.Sprintf(
					"TLS service on %s:%d presents a certificate that expired%s.",
					ip, p.Port, formatNotAfter(p.TLSNotAfter),
				),
				Remediation: "Renew the certificate; prefer a privately trusted or publicly trusted cert for admin UIs.",
				Evidence: []Evidence{{Method: "tls", Summary: fmt.Sprintf("Certificate for %q expired%s", p.TLSCommonName, formatNotAfter(p.TLSNotAfter)),
					Endpoint: endpoint, ObservedAt: at}},
				HostIP: ip,
				Port:   p.Port,
			})
		}
		if p.TLSSelfSigned {
			cn := p.TLSCommonName
			if cn == "" {
				cn = "(no CN)"
			}
			out = append(out, Finding{
				ID:         "tls-self-signed-" + strconv.Itoa(p.Port) + "-" + ip,
				Rule:       "tls-self-signed",
				Severity:   SeverityInfo,
				Category:   CategoryObservation,
				Confidence: ConfidenceConfirmed,
				Title:      "Self-signed TLS certificate",
				Description: fmt.Sprintf(
					"TLS service on %s:%d uses a self-signed certificate (CN %s). Common on LAN gear, but browsers will warn.",
					ip, p.Port, cn,
				),
				Remediation: "Replace with a cert from your internal CA or a public CA if the UI is shared; verify you trust this device.",
				Unknown:     "Whether this is the certificate you expect: compare its fingerprint with the device's settings page.",
				Evidence:    []Evidence{{Method: "tls", Summary: fmt.Sprintf("Issuer and subject match (CN %s)", cn), Endpoint: endpoint, ObservedAt: at}},
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

// SeverityRank orders severities, most severe first.
func SeverityRank(s string) int {
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
