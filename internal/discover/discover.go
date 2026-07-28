package discover

import (
	"context"
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
}

// Result is discovery output plus truncation metadata.
type Result struct {
	Hosts            []Host
	Truncated        bool
	HostsEnumerated  int
	HostsAvailable   int
}

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

	available := 0
	for _, t := range opt.Targets {
		available += netinfo.CountUsableHosts(t)
	}

	var ips []net.IP
	for _, t := range opt.Targets {
		remain := opt.MaxHosts - len(ips)
		if remain <= 0 {
			break
		}
		ips = append(ips, netinfo.HostsInCIDR(t, remain)...)
	}
	truncated := available > len(ips)
	total := len(ips)
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
	}

	if opt.UseARP && ARPSweepSupported() {
		if opt.Progress != nil {
			opt.Progress(total, total, "arp sweep")
		}
		arpTimeout := opt.Timeout
		if arpTimeout < time.Second {
			arpTimeout = 1500 * time.Millisecond
		}
		for ip, mac := range SweepARP(ctx, opt.Targets, arpTimeout) {
			if ctx.Err() != nil {
				break
			}
			if h, ok := alive[ip]; ok {
				if h.MAC == "" {
					h.MAC = mac
				}
				h.AliveVia = appendUnique(h.AliveVia, "arp")
				continue
			}
			alive[ip] = &Host{
				IP:       ip,
				MAC:      mac,
				AliveVia: []string{"arp"},
				LastSeen: time.Now(),
			}
		}
	}

	out := make([]Host, 0, len(alive))
	arpTable := ReadARPTable()
	for _, h := range alive {
		if h.MAC == "" {
			if mac, ok := arpTable[h.IP]; ok {
				h.MAC = mac
			}
		}
		h.Hostname = reverseDNS(ctx, h.IP)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipLess(out[i].IP, out[j].IP)
	})
	return Result{
		Hosts:           out,
		Truncated:       truncated,
		HostsEnumerated: total,
		HostsAvailable:  available,
	}, ctx.Err()
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
