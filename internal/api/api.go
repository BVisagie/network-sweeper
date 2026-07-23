package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/netinfo"
	"github.com/BVisagie/network-sweeper/internal/oui"
	"github.com/BVisagie/network-sweeper/internal/platform"
	"github.com/BVisagie/network-sweeper/internal/risk"
	"github.com/BVisagie/network-sweeper/internal/scan"
	"github.com/BVisagie/network-sweeper/internal/update"
	"github.com/BVisagie/network-sweeper/internal/version"
)

const TokenHeader = "X-NetworkSweeper-Token"

// Server is the hardened localhost API + static UI.
type Server struct {
	Token      string
	ListenAddr string // e.g. 127.0.0.1:12345
	BaseURL    string
	WebFS      fs.FS
	Elevated   bool

	mu           sync.Mutex
	customOptIn  bool
	updatesOptIn bool
	lastScan     *ScanSnapshot
	scanRunning  bool
	scanProgress string
	cancelScan   context.CancelFunc
}

// ScanSnapshot is the last completed scan result.
type ScanSnapshot struct {
	StartedAt        time.Time       `json:"startedAt"`
	FinishedAt       time.Time       `json:"finishedAt"`
	DurationMs       int64           `json:"durationMs"`
	Targets          []string        `json:"targets"`
	Deep             bool            `json:"deep"`
	CustomRange      bool            `json:"customRange"`
	Hosts            []discover.Host `json:"hosts"`
	Ports            []scan.Result   `json:"ports"`
	Findings         []risk.Finding  `json:"findings"`
	GatewayIP        string          `json:"gatewayIp,omitempty"`
	Error            string          `json:"error,omitempty"`
	Warning          string          `json:"warning"`
}

// New creates a server with a fresh session token.
func New(webFS fs.FS, elevated bool) *Server {
	return &Server{
		Token:    newToken(),
		WebFS:    webFS,
		Elevated: elevated,
	}
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", s.withSecurity(s.handleSession))
	mux.HandleFunc("/api/interfaces", s.withSecurity(s.handleInterfaces))
	mux.HandleFunc("/api/platform", s.withSecurity(s.handlePlatform))
	mux.HandleFunc("/api/scan", s.withSecurity(s.handleScan))
	mux.HandleFunc("/api/scan/status", s.withSecurity(s.handleScanStatus))
	mux.HandleFunc("/api/scan/cancel", s.withSecurity(s.handleScanCancel))
	mux.HandleFunc("/api/results", s.withSecurity(s.handleResults))
	mux.HandleFunc("/api/export", s.withSecurity(s.handleExport))
	mux.HandleFunc("/api/settings", s.withSecurity(s.handleSettings))
	mux.HandleFunc("/api/update", s.withSecurity(s.handleUpdate))
	mux.Handle("/", s.uiHandler())
	return mux
}

func (s *Server) withSecurity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originOK(r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if !s.tokenOK(r) {
			http.Error(w, "missing or invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	allowed := []string{
		s.BaseURL,
		strings.Replace(s.BaseURL, "127.0.0.1", "localhost", 1),
		strings.Replace(s.BaseURL, "localhost", "127.0.0.1", 1),
	}
	for _, a := range allowed {
		if a != "" && origin == a {
			return true
		}
	}
	return false
}

func (s *Server) tokenOK(r *http.Request) bool {
	tok := r.Header.Get(TokenHeader)
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return tok != "" && tok == s.Token
}

func (s *Server) uiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "/index.html" {
			data, err := fs.ReadFile(s.WebFS, "index.html")
			if err != nil {
				http.Error(w, "ui missing", http.StatusInternalServerError)
				return
			}
			html := strings.Replace(string(data), "__SESSION_TOKEN__", s.Token, 1)
			html = strings.Replace(html, "__APP_VERSION__", version.Display(), 1)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(html))
			return
		}
		name := strings.TrimPrefix(path, "/")
		b, err := fs.ReadFile(s.WebFS, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(name, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else if strings.HasSuffix(name, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		_, _ = w.Write(b)
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, map[string]any{
		"version":      version.Display(),
		"baseUrl":      s.BaseURL,
		"elevated":     s.Elevated,
		"customOptIn":  s.customOptIn,
		"updatesOptIn": s.updatesOptIn,
	})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := netinfo.ListIPv4Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	locals, _ := netinfo.LocalSubnets()
	cidrs := make([]string, 0, len(locals))
	for _, n := range locals {
		cidrs = append(cidrs, n.String())
	}
	writeJSON(w, map[string]any{
		"interfaces":     ifaces,
		"localSubnets":   cidrs,
		"discoveryPorts": discover.DiscoveryPorts,
		"findingsPorts":  scan.FindingsPorts,
		"gatewayIp":      netinfo.DefaultGatewayIPv4(),
		"localIps":       keys(netinfo.LocalIPv4Set()),
	})
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (s *Server) handlePlatform(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, platform.Snapshot(s.Elevated))
}

type scanRequest struct {
	Targets     []string `json:"targets"`
	Deep        bool     `json:"deep"`
	CustomOptIn bool     `json:"customOptIn"`
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

	var targets []*net.IPNet
	if len(req.Targets) == 0 {
		targets = local
	} else {
		for _, t := range req.Targets {
			_, n, err := net.ParseCIDR(strings.TrimSpace(t))
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid target %q", t), http.StatusBadRequest)
				return
			}
			targets = append(targets, n)
		}
	}
	if len(targets) == 0 {
		http.Error(w, "no scan targets", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	// Per-scan opt-in from the request, or Settings toggle — scan body does not permanently sticky-set settings.
	custom := req.CustomOptIn || s.customOptIn
	if s.scanRunning {
		s.mu.Unlock()
		http.Error(w, "scan already running", http.StatusConflict)
		return
	}
	s.mu.Unlock()

	if err := netinfo.RangeAllowed(targets, local, custom); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	s.mu.Lock()
	s.scanRunning = true
	s.scanProgress = "starting"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	s.cancelScan = cancel
	s.mu.Unlock()

	go s.runScan(ctx, targets, req.Deep, custom)

	writeJSON(w, map[string]any{"status": "started"})
}

func (s *Server) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	cancel := s.cancelScan
	running := s.scanRunning
	s.mu.Unlock()
	if !running || cancel == nil {
		writeJSON(w, map[string]any{"status": "idle"})
		return
	}
	cancel()
	writeJSON(w, map[string]any{"status": "canceling"})
}

func (s *Server) runScan(ctx context.Context, targets []*net.IPNet, deep, custom bool) {
	defer func() {
		s.mu.Lock()
		s.scanRunning = false
		s.cancelScan = nil
		s.mu.Unlock()
	}()

	gateway := netinfo.DefaultGatewayIPv4()
	selfIPs := netinfo.LocalIPv4Set()

	snap := &ScanSnapshot{
		StartedAt:   time.Now().UTC(),
		Deep:        deep && s.Elevated,
		CustomRange: custom,
		GatewayIP:   gateway,
		Warning:     "In unprivileged mode, a host that does not accept connections on any discovery port will not appear at all.",
	}
	for _, t := range targets {
		snap.Targets = append(snap.Targets, t.String())
	}
	useICMP := runtime.GOOS == "windows" || (deep && s.Elevated)
	if useICMP {
		snap.Warning = "A host that does not accept connections on any discovery port (and is not found via ICMP) will not appear at all."
	}
	if deep && !s.Elevated {
		if runtime.GOOS == "windows" {
			snap.Warning += " Deep discovery was requested without Admin; Windows still tries system ping as a best-effort boost. Run as administrator for more reliable quiet-host discovery."
		} else {
			snap.Warning += " Deep discovery requested but process is not elevated; ICMP is skipped. Relaunch with sudo, then enable Deep discovery."
		}
	}

	eng := discover.NewEngine()
	res, err := eng.Discover(ctx, discover.Options{
		Targets:     targets,
		Deep:        deep && s.Elevated,
		UseICMP:     useICMP,
		Concurrency: 128,
		MaxHosts:    1024,
		Progress: func(done, total int, msg string) {
			s.mu.Lock()
			s.scanProgress = fmt.Sprintf("discovery %d/%d: %s", done, total, msg)
			s.mu.Unlock()
		},
	})
	if err != nil && ctx.Err() == nil {
		snap.Error = err.Error()
	}
	if ctx.Err() != nil {
		snap.Warning += " Scan was canceled."
	}
	if res.Truncated {
		snap.Warning += fmt.Sprintf(" Address list was truncated to %d hosts (subnet(s) contain about %d usable addresses).", res.HostsEnumerated, res.HostsAvailable)
	}

	hosts := res.Hosts
	for i := range hosts {
		if hosts[i].MAC != "" {
			hosts[i].Vendor = oui.Lookup(hosts[i].MAC)
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
	snap.Hosts = hosts

	ips := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips = append(ips, h.IP)
	}
	s.mu.Lock()
	s.scanProgress = "scanning ports"
	s.mu.Unlock()

	ports, scanErr := scan.ScanHosts(ctx, ips, 350*time.Millisecond, 64)
	if scanErr != nil && ctx.Err() == nil {
		if snap.Error != "" {
			snap.Error += "; "
		}
		snap.Error += "port scan: " + scanErr.Error()
	}
	snap.Ports = ports
	snap.Findings = risk.Evaluate(hosts, ports)
	snap.FinishedAt = time.Now().UTC()
	snap.DurationMs = snap.FinishedAt.Sub(snap.StartedAt).Milliseconds()

	s.mu.Lock()
	s.lastScan = snap
	s.scanProgress = "done"
	s.mu.Unlock()
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, map[string]any{
		"running":   s.scanRunning,
		"progress":  s.scanProgress,
		"hasResult": s.lastScan != nil,
	})
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastScan == nil {
		writeJSON(w, map[string]any{"results": nil})
		return
	}
	writeJSON(w, s.lastScan)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	snap := s.lastScan
	s.mu.Unlock()
	if snap == nil {
		http.Error(w, "no results", http.StatusNotFound)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=network-sweeper.csv")
		_, _ = w.Write([]byte(exportCSV(snap)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=network-sweeper.json")
	_ = json.NewEncoder(w).Encode(snap)
}

type settingsRequest struct {
	CustomOptIn  *bool `json:"customOptIn"`
	UpdatesOptIn *bool `json:"updatesOptIn"`
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		defer s.mu.Unlock()
		writeJSON(w, map[string]any{
			"customOptIn":  s.customOptIn,
			"updatesOptIn": s.updatesOptIn,
		})
	case http.MethodPost:
		var req settingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		if req.CustomOptIn != nil {
			s.customOptIn = *req.CustomOptIn
		}
		if req.UpdatesOptIn != nil {
			s.updatesOptIn = *req.UpdatesOptIn
		}
		out := map[string]any{"customOptIn": s.customOptIn, "updatesOptIn": s.updatesOptIn}
		s.mu.Unlock()
		writeJSON(w, out)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	optIn := s.updatesOptIn
	s.mu.Unlock()
	if !optIn {
		http.Error(w, "update checks are disabled; enable in settings first", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, update.CheckLatest(ctx, nil))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func exportCSV(snap *ScanSnapshot) string {
	var b strings.Builder
	b.WriteString("ip,mac,vendor,hostname,alive_via,open_ports,finding_count,is_self,is_gateway\n")
	portsByIP := map[string][]string{}
	findCount := map[string]int{}
	for _, p := range snap.Ports {
		for _, op := range p.Ports {
			portsByIP[p.IP] = append(portsByIP[p.IP], fmt.Sprintf("%d/%s", op.Port, op.Service))
		}
	}
	for _, f := range snap.Findings {
		findCount[f.HostIP]++
	}
	for _, h := range snap.Hosts {
		row := []string{
			h.IP,
			csvField(h.MAC),
			csvField(h.Vendor),
			csvField(h.Hostname),
			csvField(strings.Join(h.AliveVia, ";")),
			csvField(strings.Join(portsByIP[h.IP], ";")),
			fmt.Sprintf("%d", findCount[h.IP]),
			fmt.Sprintf("%t", h.IsSelf),
			fmt.Sprintf("%t", h.IsGateway),
		}
		b.WriteString(strings.Join(row, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// ListenAndServe binds 127.0.0.1:0 (ephemeral), sets BaseURL/ListenAddr, and serves.
func (s *Server) ListenAndServe() (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	s.ListenAddr = ln.Addr().String()
	s.BaseURL = "http://" + s.ListenAddr
	hs := &http.Server{Handler: s.Handler()}
	go func() { _ = hs.Serve(ln) }()
	return hs, ln, nil
}
