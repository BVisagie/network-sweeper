package discover

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Host is a discovered live host.
type Host struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	AliveVia  []string `json:"aliveVia"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Options controls discovery behavior.
type Options struct {
	Targets        []*net.IPNet
	Timeout        time.Duration
	Concurrency    int
	MaxHosts       int
	Deep           bool // attempt elevated ARP/ICMP when available
	UseICMP        bool // also try ICMP (e.g. Windows unprivileged boost)
	Progress       func(done, total int, msg string)
}

// Engine runs host discovery.
type Engine struct {
	Ports []int
}

func NewEngine() *Engine {
	return &Engine{Ports: append([]int(nil), DiscoveryPorts...)}
}

// Discover finds live hosts in the given targets.
func (e *Engine) Discover(ctx context.Context, opt Options) ([]Host, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 400 * time.Millisecond
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 128
	}
	if opt.MaxHosts <= 0 {
		opt.MaxHosts = 1024
	}

	var ips []net.IP
	for _, t := range opt.Targets {
		ips = append(ips, hostsFromCIDR(t, opt.MaxHosts-len(ips))...)
		if len(ips) >= opt.MaxHosts {
			break
		}
	}
	total := len(ips)
	if opt.Progress != nil {
		opt.Progress(0, total, "starting discovery")
	}

	type result struct {
		ip   net.IP
		via  string
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

		// TCP discovery ports
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

		// ICMP: Windows unprivileged boost, or Deep discovery on any OS.
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

	// Enrich MAC from ARP cache, hostname via reverse DNS (best-effort).
	out := make([]Host, 0, len(alive))
	arpTable := ReadARPTable()
	for _, h := range alive {
		if mac, ok := arpTable[h.IP]; ok {
			h.MAC = mac
		}
		h.Hostname = reverseDNS(ctx, h.IP)
		out = append(out, *h)
	}
	return out, ctx.Err()
}

func hostsFromCIDR(cidr *net.IPNet, max int) []net.IP {
	if max <= 0 {
		return nil
	}
	ip := cidr.IP.Mask(cidr.Mask).To4()
	if ip == nil {
		return nil
	}
	ones, bits := cidr.Mask.Size()
	total := 1 << uint(bits-ones)
	start := 0
	end := total
	if ones < 31 && total > 2 {
		start = 1
		end = total - 1
	}
	base := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	var hosts []net.IP
	for i := start; i < end && len(hosts) < max; i++ {
		v := base + uint32(i)
		hosts = append(hosts, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
	}
	return hosts
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
