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
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/enrich"
	"github.com/BVisagie/network-sweeper/internal/netinfo"
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
	lastScan     *ScanSnapshot // most recent finished run, whatever its end state
	scanRunning  bool
	cancelScan   context.CancelFunc
	run          *scanRun // active or most recent run
}

// ScanSnapshot is the result of one finished run. Canceled and timed-out runs
// keep what they observed, flagged Partial.
type ScanSnapshot struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Partial     bool            `json:"partial"`
	Coverage    scanPlan        `json:"coverage"`
	StartedAt   time.Time       `json:"startedAt"`
	FinishedAt  time.Time       `json:"finishedAt"`
	DurationMs  int64           `json:"durationMs"`
	Targets     []string        `json:"targets"`
	Deep        bool            `json:"deep"`
	CustomRange bool            `json:"customRange"`
	Hosts       []discover.Host `json:"hosts"`
	Ports       []scan.Result   `json:"ports"`
	Findings    []risk.Finding  `json:"findings"`
	GatewayIP   string          `json:"gatewayIp,omitempty"`
	Error       string          `json:"error,omitempty"`
	Warning     string          `json:"warning"`
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
	mux.HandleFunc("/api/scan/preview", s.withSecurity(s.handleScanPreview))
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
		"subnets":        subnetChoices(ifaces, locals),
		"addressLimit":   scanAddressLimit,
		"discoveryPorts": discover.DiscoveryPorts,
		"findingsPorts":  scan.FindingsPorts,
		"gatewayIp":      netinfo.DefaultGatewayIPv4(),
		"localIps":       keys(netinfo.LocalIPv4Set()),
	})
}

// subnetChoice is one local subnet offered in the scan scope picker.
type subnetChoice struct {
	CIDR      string   `json:"cidr"`
	Ifaces    []string `json:"interfaces"`
	Addresses int      `json:"addresses"`
	Fits      bool     `json:"fits"` // within the per-scan address limit on its own
}

func subnetChoices(ifaces []netinfo.InterfaceInfo, locals []*net.IPNet) []subnetChoice {
	out := make([]subnetChoice, 0, len(locals))
	for _, n := range locals {
		c := subnetChoice{CIDR: n.String(), Addresses: netinfo.CountUsableHosts(n)}
		c.Fits = c.Addresses <= scanAddressLimit
		for _, i := range ifaces {
			for _, cidr := range i.CIDRs {
				if _, in, err := net.ParseCIDR(cidr); err == nil && in.String() == c.CIDR {
					c.Ifaces = append(c.Ifaces, i.Name)
					break
				}
			}
		}
		out = append(out, c)
	}
	return out
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
	b.WriteString("ip,mac,vendor,hostname,identity_hint,alive_via,open_ports,http_titles,tls_names,banners,finding_count,is_self,is_gateway,private_mac,duplicate_macs\n")
	portsByIP := map[string][]scan.OpenPort{}
	findCount := map[string]int{}
	for _, p := range snap.Ports {
		portsByIP[p.IP] = p.Ports
	}
	for _, f := range snap.Findings {
		findCount[f.HostIP]++
	}
	for _, h := range snap.Hosts {
		ports := portsByIP[h.IP]
		var open, titles, tlsNames, banners []string
		for _, op := range ports {
			open = append(open, fmt.Sprintf("%d/%s", op.Port, op.Service))
			if op.HTTPTitle != "" {
				titles = append(titles, fmt.Sprintf("%d:%s", op.Port, op.HTTPTitle))
			}
			if op.TLSCommonName != "" {
				tlsNames = append(tlsNames, fmt.Sprintf("%d:%s", op.Port, op.TLSCommonName))
			}
			if op.Banner != "" {
				banners = append(banners, fmt.Sprintf("%d:%s", op.Port, op.Banner))
			}
		}
		row := []string{
			h.IP,
			csvField(h.MAC),
			csvField(h.Vendor),
			csvField(h.Hostname),
			csvField(enrich.IdentityHint(ports)),
			csvField(strings.Join(h.AliveVia, ";")),
			csvField(strings.Join(open, ";")),
			csvField(strings.Join(titles, ";")),
			csvField(strings.Join(tlsNames, ";")),
			csvField(strings.Join(banners, ";")),
			fmt.Sprintf("%d", findCount[h.IP]),
			fmt.Sprintf("%t", h.IsSelf),
			fmt.Sprintf("%t", h.IsGateway),
			fmt.Sprintf("%t", h.PrivateMAC),
			csvField(strings.Join(h.DuplicateMACs, ";")),
		}
		b.WriteString(strings.Join(row, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

// csvField quotes s for CSV. Most cells hold text a device chose (names,
// titles, banners), so control characters become spaces, bidi overrides are
// dropped, and a leading = + - @ is prefixed with ' so a spreadsheet shows it
// as text instead of running it as a formula.
func csvField(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F:
			return -1
		case unicode.IsControl(r):
			return ' '
		}
		return r
	}, s)
	if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"") {
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
