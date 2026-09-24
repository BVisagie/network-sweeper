package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/BVisagie/network-sweeper/internal/netinfo"
)

// Host is a discovered live host.
type Host struct {
	IP                string    `json:"ip"`
	MAC               string    `json:"mac,omitempty"`
	Vendor            string    `json:"vendor,omitempty"`
	Hostname          string    `json:"hostname,omitempty"`
	AliveVia          []string  `json:"aliveVia"`
	LastSeen          time.Time `json:"lastSeen"`
	IsSelf            bool      `json:"isSelf,omitempty"`
	IsGateway         bool      `json:"isGateway,omitempty"`
	LikelyRouterGuess bool      `json:"likelyRouterGuess,omitempty"`
	UPnP              bool      `json:"upnp,omitempty"`
	UPnPFriendlyName  string    `json:"upnpFriendlyName,omitempty"`
	SNMPPublic        bool      `json:"snmpPublic,omitempty"`
	SNMPSysDescr      string    `json:"snmpSysDescr,omitempty"`
	// PrivateMAC is set when the MAC is locally administered (U/L bit) and no
	// vendor is known: typically a phone's private Wi-Fi address.
	PrivateMAC bool `json:"privateMac,omitempty"`
	// DuplicateMACs lists every MAC that answered ARP for this IP when more
	// than one did (active ARP sweep only).
	DuplicateMACs []string `json:"duplicateMacs,omitempty"`
}

// Options controls discovery behavior.
type Options struct {
	Targets     []*net.IPNet
	Timeout     time.Duration
	Concurrency int
	MaxHosts    int
	Deep        bool // elevated ICMP path when UseICMP/Deep set by caller
	UseICMP     bool // also try ICMP (e.g. Windows unprivileged boost)
	UseARP      bool // elevated active ARP sweep (Unix); ignored when unsupported
	Progress    func(done, total int, msg string)
	// OnHost, when set, is called once per live host as it is found (from a
	// single goroutine), so callers can show partial results.
	OnHost func(ip, via string)
}

// Result is discovery output.
type Result struct {
	Hosts           []Host
	HostsEnumerated int
}

// ErrTooManyAddresses is returned when targets hold more distinct addresses
// than Options.MaxHosts. Callers check the size first (netinfo.UniqueHosts).
var ErrTooManyAddresses = errors.New("targets hold more addresses than the scan limit")

// Engine runs host discovery.
type Engine struct {
	Ports []int
}

func NewEngine() *Engine {
	return &Engine{Ports: append([]int(nil), DiscoveryPorts...)}
}

// Discover finds live hosts in the given targets.
func (e *Engine) Discover(ctx context.Context, opt Options) (Result, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 400 * time.Millisecond
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 128
	}
	if opt.MaxHosts <= 0 {
		opt.MaxHosts = 1024
	}

	ips, ok := netinfo.UniqueHosts(opt.Targets, opt.MaxHosts)
	if !ok {
		return Result{}, ErrTooManyAddresses
	}
	enumerated := make(map[string]bool, len(ips))
	for _, ip := range ips {
		enumerated[ip.String()] = true
	}
	total := len(ips)
	found := func(ip, via string) {
		if opt.OnHost != nil {
			opt.OnHost(ip, via)
		}
	}
	if opt.Progress != nil {
		opt.Progress(0, total, "starting discovery")
	}

	type result struct {
		ip  net.IP
		via string
	}
	results := make(chan result, opt.Concurrency)
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	var doneCount int64
	var mu sync.Mutex

	probeOne := func(ip net.IP) {
		defer wg.Done()
		defer func() {
			mu.Lock()
			doneCount++
			d := int(doneCount)
			mu.Unlock()
			if opt.Progress != nil && (d%32 == 0 || d == total) {
				opt.Progress(d, total, fmt.Sprintf("probed %s", ip))
			}
		}()

		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		defer func() { <-sem }()

		for _, port := range e.Ports {
			if ctx.Err() != nil {
				return
			}
			addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
			d := net.Dialer{Timeout: opt.Timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				results <- result{ip: ip, via: fmt.Sprintf("tcp/%d", port)}
				return
			}
		}

		if opt.UseICMP || opt.Deep {
			if Ping(ctx, ip, opt.Timeout) {
				results <- result{ip: ip, via: "icmp"}
				return
			}
		}
	}

	wg.Add(len(ips))
	for _, ip := range ips {
		ip := ip
		go probeOne(ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	alive := map[string]*Host{}
	for r := range results {
		key := r.ip.String()
		if h, ok := alive[key]; ok {
			h.AliveVia = appendUnique(h.AliveVia, r.via)
			h.LastSeen = time.Now()
			continue
		}
		h := &Host{
			IP:       key,
			AliveVia: []string{r.via},
			LastSeen: time.Now(),
		}
		alive[key] = h
		found(key, r.via)
	}

	if opt.UseARP && ARPSweepSupported() {
		if opt.Progress != nil {
			opt.Progress(total, total, "arp sweep")
		}
		arpTimeout := opt.Timeout
		if arpTimeout < time.Second {
			arpTimeout = 1500 * time.Millisecond
		}
		for ip, macs := range SweepARP(ctx, opt.Targets, arpTimeout) {
			if ctx.Err() != nil {
				break
			}
			if !enumerated[ip] {
				continue
			}
			var dups []string
			if len(macs) > 1 {
				dups = macs
			}
			if h, ok := alive[ip]; ok {
				if h.MAC == "" {
					h.MAC = macs[0]
				}
				h.DuplicateMACs = dups
				h.AliveVia = appendUnique(h.AliveVia, "arp")
				continue
			}
			alive[ip] = &Host{
				IP:            ip,
				MAC:           macs[0],
				DuplicateMACs: dups,
				AliveVia:      []string{"arp"},
				LastSeen:      time.Now(),
			}
			found(ip, "arp")
		}
	}

	arpTable := readARPEntries()
	for _, ip := range promoteARPCache(alive, arpTable, enumerated) {
		found(ip, "arp-cache")
	}

	out := make([]Host, 0, len(alive))
	for _, h := range alive {
		if h.MAC == "" {
			if e, ok := arpTable[h.IP]; ok {
				h.MAC = e.MAC
			}
		}
		out = append(out, *h)
	}
	resolveNames(ctx, out, opt.Concurrency)
	sort.Slice(out, func(i, j int) bool {
		return ipLess(out[i].IP, out[j].IP)
	})
	return Result{Hosts: out, HostsEnumerated: total}, ctx.Err()
}

// promoteARPCache adds hosts that only the ARP cache knows about. Every TCP
// dial made the OS resolve the target's MAC first, so the cache holds on-link
// hosts that closed every discovery port: no elevation needed on any OS.
// Static rows are skipped (the OS never asked the network for them), as are
// non-unicast MACs and addresses outside the enumerated targets. It returns
// the promoted addresses.
func promoteARPCache(alive map[string]*Host, table map[string]arpEntry, enumerated map[string]bool) []string {
	var added []string
	for ip, e := range table {
		if _, ok := alive[ip]; ok || e.Static || !enumerated[ip] || !unicastMAC(e.MAC) {
			continue
		}
		alive[ip] = &Host{
			IP:       ip,
			MAC:      e.MAC,
			AliveVia: []string{"arp-cache"},
			LastSeen: time.Now(),
		}
		added = append(added, ip)
	}
	return added
}

func ipLess(a, b string) bool {
	ai := net.ParseIP(a).To4()
	bi := net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return false
}

// resolveNames fills Hostname by reverse DNS for every host, at most
// concurrency lookups at a time.
func resolveNames(ctx context.Context, hosts []Host, concurrency int) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			defer func() { <-sem }()
			h.Hostname = reverseDNS(ctx, h.IP)
		}(&hosts[i])
	}
	wg.Wait()
}

func reverseDNS(ctx context.Context, ip string) string {
	r := &net.Resolver{}
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
