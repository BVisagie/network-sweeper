// Package analysis builds a prompt, for any capable AI model, that asks for an
// assessment of a scan and hardening advice. The app never sends it anywhere:
// the user copies it. Identifying details can be masked before it leaves.
package analysis

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BVisagie/network-sweeper/internal/inventory"
	"github.com/BVisagie/network-sweeper/internal/risk"
)

//go:embed prompt.md
var promptTemplate string

// Options choose what is masked.
type Options struct {
	MaskMACs  bool
	MaskNames bool // device names, hostnames, UPnP names, certificate names, notes
}

// Finding is a finding on a device with its review state.
type Finding struct {
	risk.Finding
	Review inventory.ReviewState
}

// Device is an inventory device with the findings of its latest observation.
type Device struct {
	inventory.Device
	Findings     []Finding
	SeenInLatest bool
	New          bool
}

// Input is everything the prompt describes. Devices may include ones the
// latest scan did not see: they get references for the comparison but are not
// listed.
type Input struct {
	AppVersion string
	OS         string
	Network    string // the profile's name
	Scan       *inventory.Snapshot
	Devices    []Device
	Changes    *inventory.Comparison // nil with fewer than two scans
}

// Stats summarizes a built prompt.
type Stats struct {
	Devices  int `json:"devices"`
	Findings int `json:"findings"`
	Chars    int `json:"chars"`
	Tokens   int `json:"tokens"` // rough: four characters per token
}

type scanOut struct {
	FinishedAt      string   `json:"finishedAt"`
	State           string   `json:"state"`
	Partial         bool     `json:"partial,omitempty"`
	DurationSeconds int64    `json:"durationSeconds"`
	Ranges          []string `json:"ranges"`
	SkippedRanges   []string `json:"skippedRanges,omitempty"`
	Addresses       int      `json:"addressesChecked"`
	Methods         []string `json:"methods"`
	DeepDiscovery   bool     `json:"deepDiscovery"`
	CustomRange     bool     `json:"customRange,omitempty"`
	Elevated        *bool    `json:"ranAsAdministrator,omitempty"` // left out when the scan did not record it
	OS              string   `json:"scannerOs"`
	GatewayIP       string   `json:"gatewayIp,omitempty"`
	GatewayMAC      string   `json:"gatewayMac,omitempty"`
	Warning         string   `json:"warning,omitempty"`
}

type portOut struct {
	Port          int    `json:"port"`
	Service       string `json:"service"`
	Protocol      string `json:"confirmedProtocol,omitempty"`
	Probe         string `json:"probe,omitempty"`
	Banner        string `json:"banner,omitempty"`
	HTTPTitle     string `json:"httpTitle,omitempty"`
	HTTPServer    string `json:"httpServer,omitempty"`
	TLSCommonName string `json:"tlsCommonName,omitempty"`
	TLSIssuer     string `json:"tlsIssuer,omitempty"`
	TLSNotAfter   string `json:"tlsNotAfter,omitempty"`
	TLSSelfSigned bool   `json:"tlsSelfSigned,omitempty"`
	TLSExpired    bool   `json:"tlsExpired,omitempty"`
}

type findingOut struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Category    string   `json:"category"`
	Rule        string   `json:"rule"`
	Port        int      `json:"port,omitempty"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Unknown     string   `json:"notEstablished,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Review      string   `json:"review"`
	ReviewNote  string   `json:"reviewNote,omitempty"`
}

type deviceOut struct {
	Ref           string       `json:"ref"`
	IP            string       `json:"ip"`
	MAC           string       `json:"mac,omitempty"`
	PrivateMAC    bool         `json:"privateMac,omitempty"`
	DuplicateMACs []string     `json:"duplicateMacs,omitempty"`
	Vendor        string       `json:"vendor,omitempty"`
	Name          string       `json:"ownerName,omitempty"`
	Hostname      string       `json:"hostname,omitempty"`
	UPnPName      string       `json:"upnpName,omitempty"`
	SNMPDescr     string       `json:"snmpDescription,omitempty"`
	Roles         []string     `json:"roles,omitempty"`
	FoundVia      []string     `json:"foundVia,omitempty"`
	New           bool         `json:"newThisScan,omitempty"`
	FirstSeen     string       `json:"firstSeen,omitempty"`
	Tags          []string     `json:"tags,omitempty"`
	Notes         string       `json:"ownerNotes,omitempty"`
	Uncertain     []string     `json:"identityCaveats,omitempty"`
	Ports         []portOut    `json:"openPorts"`
	Findings      []findingOut `json:"findings"`
}

type changeOut struct {
	Device   string `json:"device,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Service  string `json:"service,omitempty"`
	Field    string `json:"field,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	Note     string `json:"note,omitempty"`
}

type changesOut struct {
	PreviousScanFinishedAt string                 `json:"previousScanFinishedAt"`
	PreviousScanPartial    bool                   `json:"previousScanPartial,omitempty"`
	CoverageDifferences    []string               `json:"coverageDifferences,omitempty"`
	Changes                map[string][]changeOut `json:"changes"`
}

type doc struct {
	GeneratedBy string      `json:"generatedBy"`
	Network     string      `json:"network,omitempty"`
	Masked      []string    `json:"masked,omitempty"`
	Scan        scanOut     `json:"scan"`
	Devices     []deviceOut `json:"devices"`
	Changes     *changesOut `json:"changesSincePreviousScan,omitempty"`
}

// Build returns the prompt text and its stats.
func Build(in Input, opt Options) (string, Stats) {
	m := newMasker(in, opt)
	d := doc{
		GeneratedBy: "Network Sweeper " + in.AppVersion,
		Network:     m.name(in.Network),
		Devices:     []deviceOut{},
	}
	if opt.MaskMACs {
		d.Masked = append(d.Masked, "MAC addresses (shown as mac-N)")
	}
	if opt.MaskNames {
		d.Masked = append(d.Masked, "device names, hostnames, UPnP and certificate names (left out, and shown as the device reference in other text)", "owner tags, notes and review notes")
	}

	if s := in.Scan; s != nil {
		d.Scan = scanOut{
			FinishedAt: day(s.FinishedAt, true), State: s.State, Partial: s.Partial,
			DurationSeconds: s.DurationMs / 1000,
			Ranges:          s.Coverage.Ranges, SkippedRanges: s.Coverage.Skipped, Addresses: s.Coverage.Addresses,
			Methods: s.Coverage.Methods, DeepDiscovery: s.Coverage.Deep, CustomRange: s.Coverage.Custom,
			Elevated: s.Coverage.Elevated, OS: in.OS,
			GatewayIP: s.GatewayIP, GatewayMAC: m.mac(s.GatewayMAC), Warning: m.text(s.Warning),
		}
	}

	var stats Stats
	for _, dev := range m.devices {
		if !dev.SeenInLatest || dev.Last == nil {
			continue
		}
		ref := m.refs[dev.ID]
		h := dev.Last.Host
		o := deviceOut{
			Ref: ref, IP: h.IP, MAC: m.mac(h.MAC), PrivateMAC: h.PrivateMAC,
			Vendor:    m.text(h.Vendor),
			Name:      m.name(dev.Name),
			Hostname:  m.name(h.Hostname),
			UPnPName:  m.name(h.UPnPFriendlyName),
			SNMPDescr: m.text(h.SNMPSysDescr),
			FoundVia:  h.AliveVia,
			New:       dev.New,
			FirstSeen: day(dev.FirstSeen, false),
			Ports:     []portOut{},
			Findings:  []findingOut{},
		}
		for _, mac := range h.DuplicateMACs {
			o.DuplicateMACs = append(o.DuplicateMACs, m.mac(mac))
		}
		if !opt.MaskNames {
			// Tags and notes are free-form, so they may hold names the
			// free-text pass cannot know: masking names leaves them out.
			o.Notes = m.text(dev.Notes)
			for _, t := range dev.Tags {
				o.Tags = append(o.Tags, m.text(t))
			}
		}
		if h.IsSelf {
			o.Roles = append(o.Roles, "the computer that ran the scan")
		}
		if h.IsGateway {
			o.Roles = append(o.Roles, "default gateway (router)")
		} else if h.LikelyRouterGuess {
			o.Roles = append(o.Roles, "possibly a router")
		}
		if h.UPnP {
			o.Roles = append(o.Roles, "answers UPnP")
		}
		if h.SNMPPublic {
			o.Roles = append(o.Roles, "answers SNMP with community \"public\"")
		}
		for _, u := range dev.Uncertain {
			o.Uncertain = append(o.Uncertain, m.text(u))
		}
		for _, p := range dev.Last.Ports {
			po := portOut{
				Port: p.Port, Service: p.Service, Protocol: p.Protocol, Probe: p.Probe,
				Banner: m.text(p.Banner), HTTPTitle: m.text(p.HTTPTitle), HTTPServer: m.text(p.HTTPServer),
				TLSCommonName: m.name(p.TLSCommonName), TLSIssuer: m.text(p.TLSIssuer),
				TLSSelfSigned: p.TLSSelfSigned, TLSExpired: p.TLSExpired,
			}
			if !p.TLSNotAfter.IsZero() {
				po.TLSNotAfter = day(p.TLSNotAfter, false)
			}
			o.Ports = append(o.Ports, po)
		}
		for _, f := range dev.Findings {
			fo := findingOut{
				Title: m.text(f.Title), Severity: f.Severity, Confidence: f.Confidence, Category: f.Category,
				Rule: f.Rule, Port: f.Port,
				Description: m.text(f.Description), Remediation: m.text(f.Remediation), Unknown: m.text(f.Unknown),
				Review: f.Review.Status,
			}
			if fo.Review == "" {
				fo.Review = "open"
			}
			if !opt.MaskNames {
				fo.ReviewNote = m.text(f.Review.Note)
			}
			for _, e := range f.Evidence {
				fo.Evidence = append(fo.Evidence, m.text(e.Summary))
			}
			o.Findings = append(o.Findings, fo)
		}
		stats.Devices++
		stats.Findings += len(o.Findings)
		d.Devices = append(d.Devices, o)
	}

	if c := in.Changes; c != nil {
		co := &changesOut{
			PreviousScanFinishedAt: day(c.Previous.FinishedAt, true),
			PreviousScanPartial:    c.Previous.Partial,
			Changes:                map[string][]changeOut{},
		}
		for _, s := range c.Scope {
			co.CoverageDifferences = append(co.CoverageDifferences, m.text(s))
		}
		groups := []struct {
			key  string
			list []inventory.Change
		}{
			{"newDevices", c.NewDevices}, {"addressChanges", c.AddressChanges}, {"devicesNotObserved", c.NotObserved},
			{"newServices", c.NewServices}, {"closedServices", c.ClosedServices}, {"servicesNoLongerAnswering", c.UnansweredServices},
			{"certificateChanges", c.CertChanges}, {"newFindings", c.NewFindings}, {"changedFindings", c.ChangedFindings},
			{"resolvedFindings", c.ResolvedFindings}, {"findingsNotSeen", c.FindingsNotSeen},
		}
		for _, g := range groups {
			for _, ch := range g.list {
				ref := m.refs[ch.DeviceID]
				from, to := m.text(ch.From), m.text(ch.To)
				if ch.Field == "certificate name" {
					// The previous name is not in the current scan, so the
					// free-text pass would not know it.
					from, to = m.name(ch.From), m.name(ch.To)
				}
				co.Changes[g.key] = append(co.Changes[g.key], changeOut{
					Device: ref, IP: ch.IP, Port: ch.Port, Service: ch.Service, Field: ch.Field,
					From: from, To: to,
					Title: m.text(ch.Title), Severity: ch.Severity, Note: m.text(ch.Note),
				})
			}
		}
		d.Changes = co
	}

	b, _ := json.Marshal(d)
	// A backtick in device text must not close the Markdown fence; \u0060 is
	// the same character to a JSON parser.
	data := strings.ReplaceAll(string(b), "`", `\u0060`)
	tmpl := strings.ReplaceAll(promptTemplate, "\r\n", "\n") // CRLF on Windows checkouts
	out := strings.Replace(tmpl, "{{DATA}}", data, 1)
	stats.Chars = len([]rune(out))
	stats.Tokens = (stats.Chars + 3) / 4
	return out, stats
}

func day(t time.Time, withTime bool) string {
	if t.IsZero() {
		return ""
	}
	if withTime {
		return t.UTC().Format("2006-01-02 15:04 UTC")
	}
	return t.UTC().Format("2006-01-02")
}

// masker gives every device a stable reference and replaces identifying
// strings wherever they appear, including inside banners and finding text.
type masker struct {
	opt     Options
	devices []Device
	refs    map[string]string // device ID -> device-N
	macs    map[string]string // canonical MAC -> mac-N
	tails   []macTail
	names   []nameSub // longest first
}

// macTail matches a MAC's last three bytes, as default network names show it.
type macTail struct {
	re    *regexp.Regexp
	token string
}

type nameSub struct {
	re  *regexp.Regexp
	ref string
	n   int // length, to replace longer names first
}

// minNameLen keeps short names ("tv", "pc") out of the free-text pass, where
// they would mangle ordinary words. Their own fields are still masked.
const minNameLen = 4

var (
	macSep    = regexp.MustCompile(`(?i)\b[0-9a-f]{1,2}[:-][0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){4}\b`)
	macDotted = regexp.MustCompile(`(?i)\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b`)
	macBare   = regexp.MustCompile(`(?i)\b[0-9a-f]{12}\b`)
	bidi      = strings.NewReplacer("\u202a", "", "\u202b", "", "\u202c", "", "\u202d", "", "\u202e", "",
		"\u2066", "", "\u2067", "", "\u2068", "", "\u2069", "", "\u200e", "", "\u200f", "", "\u061c", "")
)

func newMasker(in Input, opt Options) *masker {
	m := &masker{opt: opt, refs: map[string]string{}, macs: map[string]string{}}
	m.devices = append([]Device(nil), in.Devices...)
	sort.SliceStable(m.devices, func(i, j int) bool { return ipLess(devIP(m.devices[i]), devIP(m.devices[j])) })
	for i, d := range m.devices {
		m.refs[d.ID] = fmt.Sprintf("device-%d", i+1)
	}
	if opt.MaskMACs {
		// Number MACs in device order, so the gateway's and each device's
		// token is stable however they appear in the text.
		for _, d := range m.devices {
			m.macToken(d.MAC)
			if d.Last != nil {
				m.macToken(d.Last.Host.MAC)
				for _, mac := range d.Last.Host.DuplicateMACs {
					m.macToken(mac)
				}
			}
		}
		if in.Scan != nil {
			m.macToken(in.Scan.GatewayMAC)
		}
	}
	if opt.MaskNames {
		seen := map[string]bool{}
		add := func(s, ref string) {
			for _, v := range nameVariants(s) {
				if len(v) >= minNameLen && !seen[v] {
					seen[v] = true
					m.names = append(m.names, nameSub{nameRegexp(v), ref, len(v)})
				}
			}
		}
		add(in.Network, "[network]")
		for _, d := range m.devices {
			ref := m.refs[d.ID]
			add(d.Name, ref)
			if d.Last != nil {
				add(d.Last.Host.Hostname, ref)
				add(d.Last.Host.UPnPFriendlyName, ref)
				for _, p := range d.Last.Ports {
					add(p.TLSCommonName, ref)
				}
			}
		}
		sort.SliceStable(m.names, func(i, j int) bool { return m.names[i].n > m.names[j].n })
	}
	return m
}

// nameVariants returns a name and, for a dotted hostname, its first label:
// banners often carry the short form.
func nameVariants(s string) []string {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	if s == "" {
		return nil
	}
	out := []string{s}
	if i := strings.IndexByte(s, '.'); i > 0 && !strings.HasPrefix(s, "*") {
		out = append(out, s[:i])
	}
	return out
}

// nameRegexp matches name case-insensitively, as a whole word where the name
// starts or ends with a word character.
func nameRegexp(name string) *regexp.Regexp {
	expr := "(?i)" + regexp.QuoteMeta(name)
	if isWord(name[0]) {
		expr = `\b` + expr
	}
	if isWord(name[len(name)-1]) {
		expr += `\b`
	}
	return regexp.MustCompile(expr)
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func canonicalMAC(s string) string {
	s = strings.ToLower(s)
	var parts []string
	switch {
	case strings.Count(s, ".") == 2:
		h := strings.ReplaceAll(s, ".", "")
		for i := 0; i+2 <= len(h); i += 2 {
			parts = append(parts, h[i:i+2])
		}
	case strings.ContainsAny(s, ":-"):
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == '-' }) {
			if len(p) == 1 {
				p = "0" + p
			}
			parts = append(parts, p)
		}
	default:
		for i := 0; i+2 <= len(s); i += 2 {
			parts = append(parts, s[i:i+2])
		}
	}
	if len(parts) != 6 {
		return ""
	}
	return strings.Join(parts, ":")
}

func (m *masker) macToken(s string) string {
	c := canonicalMAC(s)
	if c == "" {
		return ""
	}
	if t, ok := m.macs[c]; ok {
		return t
	}
	t := fmt.Sprintf("mac-%d", len(m.macs)+1)
	m.macs[c] = t
	tail := strings.Split(c[len(c)-8:], ":")
	m.tails = append(m.tails, macTail{regexp.MustCompile(`(?i)\b` + strings.Join(tail, "[:-]") + `\b`), t})
	return t
}

// mac masks a MAC field.
func (m *masker) mac(s string) string {
	if s == "" || !m.opt.MaskMACs {
		return s
	}
	if t := m.macToken(s); t != "" {
		return t
	}
	return m.text(s)
}

// name masks a field that is itself an identifying name: when masking, the
// field is left out, since the device reference already names the device.
func (m *masker) name(s string) string {
	if m.opt.MaskNames {
		return ""
	}
	return m.text(s)
}

// text cleans free text: it drops bidi controls and, when masking, replaces
// every MAC-looking token and every known name.
func (m *masker) text(s string) string {
	if s == "" {
		return s
	}
	s = bidi.Replace(s)
	if m.opt.MaskMACs {
		anyMAC := func(v string) string {
			if t := m.macToken(v); t != "" {
				return t
			}
			return v
		}
		known := func(v string) string {
			if t, ok := m.macs[canonicalMAC(v)]; ok {
				return t
			}
			return v
		}
		s = macSep.ReplaceAllStringFunc(s, anyMAC)
		s = macDotted.ReplaceAllStringFunc(s, anyMAC)
		// Bare hex and three-byte tails (default network names end in one)
		// are only masked when they belong to a MAC we know.
		s = macBare.ReplaceAllStringFunc(s, known)
		for _, t := range m.tails {
			s = t.re.ReplaceAllLiteralString(s, t.token)
		}
	}
	if m.opt.MaskNames {
		for _, n := range m.names {
			s = n.re.ReplaceAllLiteralString(s, n.ref)
		}
	}
	return s
}

func devIP(d Device) string {
	if d.Last != nil {
		return d.Last.Host.IP
	}
	return d.Address
}

func ipLess(a, b string) bool {
	ai, bi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	return bytes.Compare(ai, bi) < 0
}
