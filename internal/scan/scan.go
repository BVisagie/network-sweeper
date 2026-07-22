package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// FindingsPorts are scanned on known-live hosts for service labeling and risk.
var FindingsPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
	2375, 2376, 5000, 8888, 9100,
}

// ServiceNames maps ports to common labels.
var ServiceNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPCbind",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8000:  "HTTP-Alt",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	2375:  "Docker API",
	2376:  "Docker API TLS",
	5000:  "HTTP-Dev",
	8888:  "HTTP-Alt",
	9100:  "Printer",
}

// OpenPort is an open TCP port with a service label.
type OpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// Result is per-host findings scan output.
type Result struct {
	IP    string     `json:"ip"`
	Ports []OpenPort `json:"ports"`
}

// ScanHosts probes findings ports on each host IP.
func ScanHosts(ctx context.Context, ips []string, timeout time.Duration, concurrency int) ([]Result, error) {
	if timeout <= 0 {
		timeout = 350 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 64
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := make([]Result, 0, len(ips))

	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports := scanHost(ctx, ip, timeout, sem)
			mu.Lock()
			out = append(out, Result{IP: ip, Ports: ports})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out, ctx.Err()
}

func scanHost(ctx context.Context, ip string, timeout time.Duration, sem chan struct{}) []OpenPort {
	var ports []OpenPort
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range FindingsPorts {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			_ = conn.Close()
			name := ServiceNames[port]
			if name == "" {
				name = "unknown"
			}
			mu.Lock()
			ports = append(ports, OpenPort{Port: port, Service: name})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return ports
}
