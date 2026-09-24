package inventory

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/risk"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// ScanRef describes one side of a comparison.
type ScanRef struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	State     string    `json:"state"`
	Partial   bool      `json:"partial"`
	Ranges    []string  `json:"ranges"`
	Methods   []string  `json:"methods"`
}

// DeviceRef names a device in a change.
type DeviceRef struct {
	DeviceID string `json:"deviceId"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
}

// Change is one difference between two scans. From and To hold the previous
// and current values where both exist; Note qualifies what the change proves.
type Change struct {
	DeviceRef
	Port     int    `json:"port,omitempty"`
	Service  string `json:"service,omitempty"`
	Field    string `json:"field,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Comparison lists what changed between a previous and a current scan of the
// same network. Absence is reported as "not observed" unless a direct check
// supports more.
type Comparison struct {
	Current  ScanRef  `json:"current"`
	Previous ScanRef  `json:"previous"`
	Scope    []string `json:"scope"` // differences in coverage that limit what the comparison proves

	NewDevices         []Change `json:"newDevices"`
	AddressChanges     []Change `json:"addressChanges"`
	NotObserved        []Change `json:"notObserved"`
	NewServices        []Change `json:"newServices"`
	ClosedServices     []Change `json:"closedServices"`     // refused the connection now
	UnansweredServices []Change `json:"unansweredServices"` // open before, no answer now: not proof of closure
	CertChanges        []Change `json:"certChanges"`
	NewFindings        []Change `json:"newFindings"`
	ChangedFindings    []Change `json:"changedFindings"`
	ResolvedFindings   []Change `json:"resolvedFindings"`
	FindingsNotSeen    []Change `json:"findingsNotSeen"`
}

type deviceView struct {
	host     discover.Host
	ports    map[int]scan.OpenPort
	closed   map[int]bool
	findings map[string]risk.Finding
}

func indexSnapshot(snap *Snapshot) map[string]*deviceView {
	portsByIP := map[string]scan.Result{}
	for _, r := range snap.Ports {
		portsByIP[r.IP] = r
	}
	byIP := map[string]*deviceView{}
	out := map[string]*deviceView{}
	for _, h := range snap.Hosts {
		if h.DeviceID == "" {
			continue
		}
		v := &deviceView{host: h, ports: map[int]scan.OpenPort{}, closed: map[int]bool{}, findings: map[string]risk.Finding{}}
		r := portsByIP[h.IP]
		for _, op := range r.Ports {
			v.ports[op.Port] = op
		}
		for _, p := range r.Closed {
			v.closed[p] = true
		}
		out[h.DeviceID] = v
		byIP[h.IP] = v
	}
	for _, f := range snap.Findings {
		if v := byIP[f.HostIP]; v != nil {
			v.findings[f.Key()] = f
		}
	}
	return out
}

func ref(snap *Snapshot) ScanRef {
	return ScanRef{
		ID: snap.ID, StartedAt: snap.StartedAt, State: snap.State, Partial: snap.Partial,
		Ranges: snap.Coverage.Ranges, Methods: snap.Coverage.Methods,
	}
}

// Compare loads two retained scans of the same profile and compares them.
// Empty IDs pick the newest scan and the one before it.
func (s *Store) Compare(profileID, currentID, previousID string) (*Comparison, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for i := len(s.inv.Scans) - 1; i >= 0; i-- {
		if e := s.inv.Scans[i]; e.ProfileID == profileID {
			ids = append(ids, e.ID)
		}
	}
	if currentID == "" && len(ids) > 0 {
		currentID = ids[0]
	}
	if previousID == "" {
		for i, id := range ids {
			if id == currentID && i+1 < len(ids) {
				previousID = ids[i+1]
			}
		}
	}
	if currentID == "" || previousID == "" {
		return nil, fmt.Errorf("at least two scans of this network are needed for a comparison")
	}
	cur, err := s.loadSnapshot(currentID)
	if err != nil {
		return nil, err
	}
	prev, err := s.loadSnapshot(previousID)
	if err != nil {
		return nil, err
	}
	if cur.ProfileID != prev.ProfileID {
		return nil, fmt.Errorf("these scans are from different networks and cannot be compared")
	}
	names := map[string]string{}
	for _, d := range s.inv.Devices {
		names[d.ID] = d.Name
	}
	return compare(cur, prev, names), nil
}

func compare(cur, prev *Snapshot, names map[string]string) *Comparison {
	c := &Comparison{Current: ref(cur), Previous: ref(prev)}
	c.Scope = scopeNotes(cur, prev)
	cv, pv := indexSnapshot(cur), indexSnapshot(prev)
	curScope := parseRanges(cur.Coverage.Ranges)
	prevScope := parseRanges(prev.Coverage.Ranges)

	dref := func(id string, v *deviceView) DeviceRef {
		name := names[id]
		if name == "" {
			name = v.host.Hostname
		}
		if name == "" {
			name = v.host.Vendor
		}
		return DeviceRef{DeviceID: id, Name: name, IP: v.host.IP}
	}

	for _, id := range sortedKeys(cv) {
		after := cv[id]
		before, seen := pv[id]
		if !seen {
			ch := Change{DeviceRef: dref(id, after)}
			switch {
			case !inScope(prevScope, after.host.IP):
				ch.Note = "The previous scan did not cover this address."
			case prev.Partial:
				ch.Note = "The previous scan was partial and may have missed it."
			}
			c.NewDevices = append(c.NewDevices, ch)
			continue
		}
		dr := dref(id, after)
		if before.host.IP != after.host.IP {
			c.AddressChanges = append(c.AddressChanges, Change{DeviceRef: dr, Field: "ip", From: before.host.IP, To: after.host.IP})
		}
		for _, port := range sortedPorts(after.ports) {
			if _, was := before.ports[port]; !was {
				c.NewServices = append(c.NewServices, Change{DeviceRef: dr, Port: port, Service: after.ports[port].Service})
			}
		}
		for _, port := range sortedPorts(before.ports) {
			if _, still := after.ports[port]; still {
				c.CertChanges = append(c.CertChanges, certChanges(dr, before.ports[port], after.ports[port])...)
				continue
			}
			ch := Change{DeviceRef: dr, Port: port, Service: before.ports[port].Service}
			if after.closed[port] {
				c.ClosedServices = append(c.ClosedServices, ch)
			} else {
				ch.Note = "No answer this time (timeout or skipped). That does not prove it closed."
				c.UnansweredServices = append(c.UnansweredServices, ch)
			}
		}
		for _, key := range sortedKeys(after.findings) {
			f := after.findings[key]
			old, had := before.findings[key]
			switch {
			case !had:
				c.NewFindings = append(c.NewFindings, findingChange(dr, f, ""))
			case old.Severity != f.Severity || old.Confidence != f.Confidence:
				ch := findingChange(dr, f, "")
				ch.From = old.Severity + " / " + old.Confidence
				ch.To = f.Severity + " / " + f.Confidence
				c.ChangedFindings = append(c.ChangedFindings, ch)
			}
		}
		for _, key := range sortedKeys(before.findings) {
			if _, still := after.findings[key]; still {
				continue
			}
			f := before.findings[key]
			if f.Port != 0 && after.closed[f.Port] {
				c.ResolvedFindings = append(c.ResolvedFindings, findingChange(dr, f, "The port now refuses connections."))
			} else {
				c.FindingsNotSeen = append(c.FindingsNotSeen, findingChange(dr, f, "Not reported this time, but nothing directly confirmed it was fixed."))
			}
		}
	}

	outside := 0
	for _, id := range sortedKeys(pv) {
		if _, still := cv[id]; still {
			continue
		}
		before := pv[id]
		if !inScope(curScope, before.host.IP) {
			outside++
			continue
		}
		ch := Change{DeviceRef: dref(id, before), Note: "Not observed in the current scan. Devices that sleep or ignore probes can be missed."}
		if cur.Partial {
			ch.Note = "Not observed, but the current scan was partial, so it may simply not have been checked."
		}
		c.NotObserved = append(c.NotObserved, ch)
	}
	if outside > 0 {
		c.Scope = append(c.Scope, fmt.Sprintf("%d device(s) from the previous scan are outside the current scan's ranges and are left out.", outside))
	}
	return c
}

func findingChange(dr DeviceRef, f risk.Finding, note string) Change {
	return Change{DeviceRef: dr, Port: f.Port, Field: f.Key(), Title: f.Title, Severity: f.Severity, Note: note}
}

func certChanges(dr DeviceRef, before, after scan.OpenPort) []Change {
	var out []Change
	add := func(field, from, to string) {
		if from != to && (from != "" || to != "") {
			out = append(out, Change{DeviceRef: dr, Port: after.Port, Field: field, From: from, To: to})
		}
	}
	// Only compare when both scans completed a handshake; a missed probe is not a change.
	if before.TLSNotAfter.IsZero() || after.TLSNotAfter.IsZero() {
		return nil
	}
	add("certificate name", before.TLSCommonName, after.TLSCommonName)
	add("certificate issuer", before.TLSIssuer, after.TLSIssuer)
	add("certificate expiry", before.TLSNotAfter.Format("2006-01-02"), after.TLSNotAfter.Format("2006-01-02"))
	return out
}

func scopeNotes(cur, prev *Snapshot) []string {
	var notes []string
	if a, b := strings.Join(prev.Coverage.Ranges, ", "), strings.Join(cur.Coverage.Ranges, ", "); a != b {
		notes = append(notes, fmt.Sprintf("Ranges differ: previous %s; current %s.", a, b))
	}
	onlyPrev, onlyCur := setDiff(prev.Coverage.Methods, cur.Coverage.Methods), setDiff(cur.Coverage.Methods, prev.Coverage.Methods)
	if len(onlyPrev) > 0 {
		notes = append(notes, "Only the previous scan used: "+strings.Join(onlyPrev, ", ")+". Devices it found that way may not appear now.")
	}
	if len(onlyCur) > 0 {
		notes = append(notes, "Only the current scan used: "+strings.Join(onlyCur, ", ")+". Some \"new\" devices may have been there before.")
	}
	if cur.Partial {
		notes = append(notes, "The current scan is partial ("+strings.ReplaceAll(cur.State, "_", " ")+"): missing devices and services may simply not have been checked.")
	}
	if prev.Partial {
		notes = append(notes, "The previous scan was partial ("+strings.ReplaceAll(prev.State, "_", " ")+"): some \"new\" items may have been missed then.")
	}
	return notes
}

func setDiff(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

func parseRanges(ranges []string) []*net.IPNet {
	var out []*net.IPNet
	for _, r := range ranges {
		if _, n, err := net.ParseCIDR(r); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func inScope(nets []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(ip)
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPorts(m map[int]scan.OpenPort) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
