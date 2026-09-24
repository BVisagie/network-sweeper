package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/enrich"
	"github.com/BVisagie/network-sweeper/internal/inventory"
	"github.com/BVisagie/network-sweeper/internal/netinfo"
	"github.com/BVisagie/network-sweeper/internal/oui"
	"github.com/BVisagie/network-sweeper/internal/risk"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// scanAddressLimit caps distinct addresses per run until discovery uses
// bounded work queues.
const scanAddressLimit = 1024

const scanTimeout = 10 * time.Minute

// Run states.
const (
	stateStarting  = "starting"
	stateRunning   = "running"
	stateCompleted = "completed"
	stateCanceled  = "canceled"
	stateTimedOut  = "timed_out"
	stateFailed    = "failed"
)

// Run phases, in order.
const (
	phaseStarting  = "starting"
	phaseDiscovery = "discovery"
	phasePorts     = "ports"
	phaseServices  = "services"
	phaseNames     = "names"
	phaseIdentity  = "identity"
	phaseSaving    = "saving"
	phaseDone      = "done"
)

type scanRequest struct {
	Targets     []string `json:"targets"`
	Deep        bool     `json:"deep"`
	CustomOptIn bool     `json:"customOptIn"`
}

// scanPlan is what a run will cover. Preview and scan build it the same way,
// so the preview shows exactly what the scan does.
type scanPlan struct {
	inventory.Coverage

	targets       []*net.IPNet
	deepRequested bool
	useICMP       bool
	useARP        bool
}

type liveHost struct {
	IP  string `json:"ip"`
	Via string `json:"via"`
}

// scanRun is the lifecycle of one run, as reported by /api/scan/status.
type scanRun struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	Phase      string     `json:"phase"`
	Done       int        `json:"done"`
	Total      int        `json:"total"`
	Found      []liveHost `json:"found"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt time.Time  `json:"finishedAt,omitzero"`
	Partial    bool       `json:"partial"`
	Error      string     `json:"error,omitempty"`
	SaveError  string     `json:"saveError,omitempty"` // results are shown but were not saved
	Plan       scanPlan   `json:"plan"`
}

// planError carries the HTTP status for a rejected plan.
type planError struct {
	status int
	msg    string
}

func (e *planError) Error() string { return e.msg }

// planScan parses and sizes the requested targets. With no targets it uses the
// local subnets that fit the limit on their own, listing the others as skipped.
func (s *Server) planScan(req scanRequest, local []*net.IPNet) (*scanPlan, error) {
	plan := &scanPlan{Coverage: inventory.Coverage{Limit: scanAddressLimit}}
	var targets []*net.IPNet
	if len(req.Targets) == 0 {
		for _, n := range local {
			if netinfo.CountUsableHosts(n) > scanAddressLimit {
				plan.Skipped = append(plan.Skipped, n.String())
				continue
			}
			targets = append(targets, n)
		}
	} else {
		for _, t := range req.Targets {
			_, n, err := net.ParseCIDR(strings.TrimSpace(t))
			if err != nil {
				return plan, &planError{http.StatusBadRequest, fmt.Sprintf("invalid target %q", t)}
			}
			if n.IP.To4() == nil {
				return plan, &planError{http.StatusBadRequest, fmt.Sprintf("%s is IPv6; only IPv4 ranges can be scanned in this version", t)}
			}
			targets = append(targets, n)
		}
	}
	seen := map[string]bool{}
	for _, n := range targets {
		if seen[n.String()] {
			continue
		}
		seen[n.String()] = true
		plan.targets = append(plan.targets, n)
		plan.Ranges = append(plan.Ranges, n.String())
	}
	if len(plan.targets) == 0 {
		return plan, &planError{http.StatusBadRequest, "no scan targets"}
	}

	plan.deepRequested = req.Deep
	plan.Deep = req.Deep && s.Elevated
	plan.useICMP = runtime.GOOS == "windows" || plan.Deep
	plan.useARP = plan.Deep && discover.ARPSweepSupported()
	plan.Methods = []string{"tcp"}
	if plan.useICMP {
		plan.Methods = append(plan.Methods, "icmp")
	}
	if plan.useARP {
		plan.Methods = append(plan.Methods, "arp-sweep")
	}
	plan.Methods = append(plan.Methods, "arp-cache", "ports", "services", "names", "ssdp", "snmp")

	ips, ok := netinfo.UniqueHosts(plan.targets, scanAddressLimit)
	if !ok {
		n := 0
		for _, t := range plan.targets {
			n += netinfo.CountUsableHosts(t)
		}
		plan.Addresses = n
		return plan, &planError{http.StatusBadRequest, fmt.Sprintf(
			"The selection holds about %d addresses; one scan covers at most %d. Choose fewer ranges or a smaller one, such as a /24 inside it.",
			n, scanAddressLimit)}
	}
	plan.Addresses = len(ips)
	return plan, nil
}

func (s *Server) handleScanPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	local, err := netinfo.LocalSubnets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	plan, err := s.planScan(req, local)
	out := map[string]any{"plan": plan, "ok": err == nil}
	if err != nil {
		out["problem"] = err.Error()
	} else {
		s.mu.Lock()
		custom := req.CustomOptIn || s.customOptIn
		s.mu.Unlock()
		if rangeErr := netinfo.RangeAllowed(plan.targets, local, custom); rangeErr != nil {
			out["ok"] = false
			out["problem"] = rangeErr.Error()
			out["needsOptIn"] = true
		}
	}
	writeJSON(w, out)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	local, err := netinfo.LocalSubnets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	plan, err := s.planScan(req, local)
	var pe *planError
	if errors.As(err, &pe) {
		http.Error(w, pe.msg, pe.status)
		return
	}

	ctx, id, err := s.reserveScan(plan, local, req.CustomOptIn)
	if errors.Is(err, errScanRunning) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	go s.runScan(ctx, id, plan)

	writeJSON(w, map[string]any{"status": "started", "id": id})
}

var errScanRunning = errors.New("scan already running")

// reserveScan checks the range and claims the single scan slot under one lock,
// so simultaneous requests cannot both start a scan.
func (s *Server) reserveScan(plan *scanPlan, local []*net.IPNet, customOptIn bool) (context.Context, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanRunning {
		return nil, "", errScanRunning
	}
	// Per-scan opt-in from the request, or Settings toggle — scan body does not permanently sticky-set settings.
	custom := customOptIn || s.customOptIn
	if err := netinfo.RangeAllowed(plan.targets, local, custom); err != nil {
		return nil, "", err
	}
	plan.Custom = custom
	id := newScanID()
	s.scanRunning = true
	s.run = &scanRun{
		ID:        id,
		State:     stateStarting,
		Phase:     phaseStarting,
		StartedAt: time.Now().UTC(),
		Plan:      *plan,
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	s.cancelScan = cancel
	return ctx, id, nil
}

func newScanID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

func (s *Server) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	cancel := s.cancelScan
	running := s.scanRunning
	current := ""
	if s.run != nil {
		current = s.run.ID
	}
	s.mu.Unlock()
	if !running || cancel == nil || (req.ID != "" && req.ID != current) {
		writeJSON(w, map[string]any{"status": "idle"})
		return
	}
	cancel()
	writeJSON(w, map[string]any{"status": "canceling", "id": current})
}

// progress updates the run's phase and counters, ignoring stale runs. Counters
// never move backwards within a phase.
func (s *Server) progress(id, phase string, done, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil || s.run.ID != id {
		return
	}
	if s.run.Phase == phase && done < s.run.Done {
		return
	}
	s.run.State = stateRunning
	s.run.Phase = phase
	s.run.Done = done
	s.run.Total = total
}

func (s *Server) addLive(id, ip, via string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil || s.run.ID != id {
		return
	}
	s.run.Found = append(s.run.Found, liveHost{IP: ip, Via: via})
}

func (s *Server) runScan(ctx context.Context, id string, plan *scanPlan) {
	defer func() {
		s.mu.Lock()
		s.scanRunning = false
		s.cancelScan = nil
		s.mu.Unlock()
	}()

	gateway := netinfo.DefaultGatewayIPv4()
	selfIPs := netinfo.LocalIPv4Set()

	s.mu.Lock()
	startedAt := s.run.StartedAt
	s.mu.Unlock()
	snap := &ScanSnapshot{
		ID:          id,
		Coverage:    plan.Coverage,
		StartedAt:   startedAt,
		Targets:     plan.Ranges,
		Deep:        plan.Deep,
		CustomRange: plan.Custom,
		GatewayIP:   gateway,
		Warning:     "In unprivileged mode, a host that does not accept connections on any discovery port appears only if it answered the OS's ARP lookup (arp-cache); hosts off the local segment will not appear at all.",
	}
	if plan.useICMP || plan.useARP {
		snap.Warning = "A host that does not accept connections on any discovery port (and is not found via ICMP"
		if plan.useARP {
			snap.Warning += "/ARP"
		}
		snap.Warning += ") and is not in the OS ARP cache will not appear at all."
	}
	if plan.deepRequested && !s.Elevated {
		if runtime.GOOS == "windows" {
			snap.Warning += " Deep discovery was requested without Admin; Windows still tries system ping as a best-effort boost. Run as administrator for more reliable quiet-host discovery. Active ARP sweep is not available on Windows in this version."
		} else {
			snap.Warning += " Deep discovery requested but process is not elevated; ICMP/ARP are skipped. Relaunch with sudo, then enable Deep discovery."
		}
	}

	s.progress(id, phaseDiscovery, 0, plan.Addresses)
	eng := discover.NewEngine()
	res, err := eng.Discover(ctx, discover.Options{
		Targets:     plan.targets,
		Deep:        plan.Deep,
		UseICMP:     plan.useICMP,
		UseARP:      plan.useARP,
		Concurrency: 128,
		MaxHosts:    scanAddressLimit,
		Progress: func(done, total int, _ string) {
			s.progress(id, phaseDiscovery, done, total)
		},
		OnHost: func(ip, via string) { s.addLive(id, ip, via) },
	})
	if err != nil && ctx.Err() == nil {
		snap.Error = err.Error()
	}

	hosts := res.Hosts
	for i := range hosts {
		if hosts[i].MAC != "" {
			hosts[i].Vendor = oui.Lookup(hosts[i].MAC)
			hosts[i].PrivateMAC = hosts[i].Vendor == "" && oui.LocallyAdministered(hosts[i].MAC)
		}
		if selfIPs[hosts[i].IP] {
			hosts[i].IsSelf = true
		}
		if gateway != "" && hosts[i].IP == gateway {
			hosts[i].IsGateway = true
		} else if gateway == "" && netinfo.LooksLikeCommonRouter(hosts[i].IP) {
			hosts[i].LikelyRouterGuess = true
		}
	}

	ips := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips = append(ips, h.IP)
	}
	s.progress(id, phasePorts, 0, len(ips))
	ports, scanErr := scan.ScanHosts(ctx, ips, 350*time.Millisecond, 64, func(done, total int) {
		s.progress(id, phasePorts, done, total)
	})
	if scanErr != nil && ctx.Err() == nil {
		if snap.Error != "" {
			snap.Error += "; "
		}
		snap.Error += "port scan: " + scanErr.Error()
	}
	s.progress(id, phaseServices, 0, 0)
	ports = enrich.Results(ctx, ports, 800*time.Millisecond, 32)
	s.progress(id, phaseNames, 0, 0)
	discover.EnrichHostnames(ctx, hosts, 400*time.Millisecond, 32, 1500*time.Millisecond)
	s.progress(id, phaseIdentity, 0, 0)
	discover.EnrichLANIdentity(ctx, hosts)
	snap.Hosts = hosts
	snap.Ports = ports
	snap.Findings = risk.Evaluate(hosts, ports)
	snap.FinishedAt = time.Now().UTC()
	snap.DurationMs = snap.FinishedAt.Sub(snap.StartedAt).Milliseconds()

	snap.GatewayMAC, snap.GatewaySubnet = gatewayIdentity(gateway, hosts)

	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		snap.State = stateCanceled
		snap.Partial = true
		snap.Warning += " The scan was stopped before it finished; these results are partial."
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		snap.State = stateTimedOut
		snap.Partial = true
		snap.Warning += fmt.Sprintf(" The scan hit the %d-minute limit; these results are partial.", int(scanTimeout.Minutes()))
	case snap.Error != "":
		snap.State = stateFailed
		snap.Partial = true
	default:
		snap.State = stateCompleted
	}

	s.progress(id, phaseSaving, 0, 0)
	// Record links hosts to devices even when the write fails; the scan stays
	// visible and exportable either way.
	saveErr := s.Store.Record(snap)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil || s.run.ID != id {
		return
	}
	s.lastScan = snap
	if saveErr != nil {
		s.run.SaveError = saveErr.Error()
	}
	s.run.State = snap.State
	s.run.Phase = phaseDone
	s.run.Partial = snap.Partial
	s.run.Error = snap.Error
	s.run.FinishedAt = snap.FinishedAt
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{
		"running":   s.scanRunning,
		"progress":  "",
		"hasResult": s.lastScan != nil,
	}
	if s.run != nil {
		run := *s.run
		run.Found = append([]liveHost(nil), s.run.Found...)
		out["scan"] = run
		out["progress"] = progressText(run)
	}
	writeJSON(w, out)
}

// gatewayIdentity returns the gateway's MAC (from the scan, else the OS ARP
// cache) and the local subnet holding it: together they name the network.
func gatewayIdentity(gateway string, hosts []discover.Host) (mac, subnet string) {
	if gateway == "" {
		return "", ""
	}
	for _, h := range hosts {
		if h.IP == gateway {
			mac = h.MAC
		}
	}
	if mac == "" {
		mac = discover.ReadARPTable()[gateway]
	}
	gw := net.ParseIP(gateway)
	if locals, err := netinfo.LocalSubnets(); err == nil {
		for _, n := range locals {
			if n.Contains(gw) {
				subnet = n.String()
				break
			}
		}
	}
	return mac, subnet
}

// progressText keeps the legacy one-line status for older clients.
func progressText(run scanRun) string {
	if run.Phase == phaseDiscovery {
		return fmt.Sprintf("discovery %d/%d", run.Done, run.Total)
	}
	if run.Phase == phaseDone {
		return "done"
	}
	return run.Phase
}
