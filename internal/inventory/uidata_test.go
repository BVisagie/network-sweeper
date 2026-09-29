package inventory

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/risk"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// TestWriteUIData regenerates testdata/ui, the synthetic data directory used
// to check the web UI without scanning a network. It runs only when asked:
//
//	NS_WRITE_UI_DATA=1 go test ./internal/inventory -run TestWriteUIData
//
// Every address is in a documentation range (192.0.2.0/24, 198.51.100.0/24),
// so a rescan from the UI never reaches a real device.
func TestWriteUIData(t *testing.T) {
	if os.Getenv("NS_WRITE_UI_DATA") == "" {
		t.Skip("set NS_WRITE_UI_DATA=1 to regenerate testdata/ui")
	}
	dir := filepath.Join("..", "..", "testdata", "ui")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	s := Open(dir)
	if st := s.Status(); st.Mode != ModePersistent {
		t.Fatalf("store not persistent: %+v", st)
	}
	defer func() {
		s.Close()
		os.Remove(filepath.Join(dir, lockName))
	}()
	saved := now
	defer func() { now = saved }()

	record := func(snap *Snapshot) {
		t.Helper()
		snap.Findings = risk.EvaluateAt(snap.Hosts, snap.Ports, snap.FinishedAt)
		snap.StartedAt = snap.FinishedAt.Add(-time.Duration(40+len(snap.Hosts)*3) * time.Second)
		snap.DurationMs = snap.FinishedAt.Sub(snap.StartedAt).Milliseconds()
		now = func() time.Time { return snap.FinishedAt.Add(20 * time.Minute) }
		if err := s.Record(snap); err != nil {
			t.Fatal(err)
		}
	}
	find := func(snap *Snapshot, ip string) string {
		t.Helper()
		for _, h := range snap.Hosts {
			if h.IP == ip {
				return h.DeviceID
			}
		}
		t.Fatalf("%s not in %s", ip, snap.ID)
		return ""
	}
	annotate := func(snap *Snapshot, ip, name, notes string, tags ...string) {
		t.Helper()
		a := Annotation{Name: &name, Tags: &tags}
		if notes != "" {
			a.Notes = &notes
		}
		if _, err := s.Annotate(find(snap, ip), a); err != nil {
			t.Fatal(err)
		}
	}
	ack := func(snap *Snapshot, ip, key, note string) {
		t.Helper()
		if _, err := s.SetReview(find(snap, ip), key, true, note); err != nil {
			t.Fatalf("ack %s %s: %v", ip, key, err)
		}
	}

	// Office: an older network with two scans, the latest cut short.
	office := uiNetwork{prefix: "198.51.100.", gwMAC: "00:1b:17:4e:20:01", deep: false}
	officeHosts := func(at time.Time, all bool) ([]discover.Host, []scan.Result) {
		n := office.hosts(at)
		n.add(1, "00:1b:17:4e:20:01", "Palo Alto Networks", "fw-office", []string{"tcp/443"}, 443)
		n.add(10, "00:50:56:a1:10:10", "VMware, Inc.", "sql-01.corp.example", []string{"tcp/445"}, 135, 139, 445, 1433, 3389)
		n.add(11, "00:15:5d:0b:11:11", "Microsoft Corporation", "reception-pc", []string{"tcp/445"}, 135, 445, 3389)
		n.add(12, "3c:52:82:61:12:12", "HP Inc.", "npi-office-printer", []string{"tcp/80"}, 80, 443, 9100)
		n.add(20, "00:04:f2:30:20:20", "Polycom", "", []string{"tcp/80"}, 80)
		if all {
			n.add(30, "00:1a:a0:77:30:30", "Dell Inc.", "build-agent-3", []string{"tcp/22"}, 22, 2376, 5432, 8080)
			n.add(31, "b8:27:eb:12:31:31", "Raspberry Pi Foundation", "door-controller", []string{"tcp/22"}, 22, 23)
		}
		n.host(20).SNMPPublic = true
		n.host(20).SNMPSysDescr = "Polycom VVX 411 conference phone"
		return n.done()
	}
	o1 := office.snapshot("s-office-1", time.Date(2026, 9, 22, 9, 5, 0, 0, time.UTC), "completed", false)
	o1.Hosts, o1.Ports = officeHosts(o1.FinishedAt, true)
	record(o1)
	if err := s.RenameProfile(o1.ProfileID, "Office"); err != nil {
		t.Fatal(err)
	}
	annotate(o1, "198.51.100.10", "SQL server", "Finance database. Owned by the accounts team.", "finance", "server")
	annotate(o1, "198.51.100.11", "Reception PC", "", "front-desk")
	o2 := office.snapshot("s-office-2", time.Date(2026, 9, 26, 16, 40, 0, 0, time.UTC), "timed_out", true)
	o2.Hosts, o2.Ports = officeHosts(o2.FinishedAt, false)
	o2.Warning += " The scan hit the 20-minute limit; these results are partial."
	record(o2)

	// Home: four scans, one stopped early, with every review state, a new
	// device, a missing one, and devices whose names and tags are long.
	home := uiNetwork{prefix: "192.0.2.", gwMAC: "f0:9f:c2:6a:00:01"}
	homeHosts := func(at time.Time, scanNo int) ([]discover.Host, []scan.Result) {
		n := home.hosts(at)
		gw := n.add(1, "f0:9f:c2:6a:00:01", "Ubiquiti Inc", "unifi.localdomain", []string{"tcp/443"}, 22, 53, 80, 443)
		gw.IsGateway = true
		n.port(1, 80).Protocol, n.port(1, 80).HTTPTitle, n.port(1, 80).Probe = "HTTP", "UniFi OS", "answered"
		n.port(1, 443).TLSCommonName, n.port(1, 443).TLSIssuer, n.port(1, 443).TLSSelfSigned = "unifi.local", "unifi.local", true
		n.port(1, 443).TLSNotAfter = time.Date(2031, 3, 1, 0, 0, 0, 0, time.UTC)
		if scanNo >= 4 {
			n.add(2, "8c:79:f5:22:02:02", "Samsung Electronics Co.,Ltd", "living-room-tv", []string{"tcp/8001"}, 80, 443, 8001, 8080)
		}
		n.add(3, "00:11:32:9a:03:03", "Synology Incorporated", "nas-01", []string{"tcp/445"}, 22, 80, 111, 139, 443, 445, 5000, 5001, 8080)
		n.port(3, 5000).Protocol, n.port(3, 5000).HTTPTitle, n.port(3, 5000).Probe = "HTTP", "Synology DiskStation - nas-01", "answered"
		self := n.add(4, "f4:7b:09:1c:04:04", "Intel Corporate", "framework-laptop", []string{"tcp/22"}, 22, 631, 5000, 7000)
		self.IsSelf = true
		n.add(5, "f0:9f:c2:6a:05:05", "Ubiquiti Inc", "upstairs-hallway-ap-u6-lite-ceiling-mount.localdomain", []string{"tcp/22"}, 22, 80, 443, 8080)
		if scanNo >= 3 {
			phone := n.add(6, "2a:4f:19:c0:06:06", "", "", []string{"arp-cache"})
			phone.PrivateMAC = true
		}
		legacy := n.add(7, "00:0c:29:4d:07:07", "VMware, Inc.", "garage-pc", []string{"tcp/23"}, 21, 23, 80, 5900)
		n.port(7, 23).Protocol, n.port(7, 23).Probe, n.port(7, 23).Banner = "Telnet", "answered", "garage-pc login:"
		n.port(7, 21).Protocol, n.port(7, 21).Probe, n.port(7, 21).Banner = "FTP", "answered", "220 (vsFTPd 3.0.3)"
		legacy.AliveVia = append(legacy.AliveVia, "icmp")
		n.add(8, "dc:a6:32:5e:08:08", "Raspberry Pi Trading Ltd", "devbox", []string{"tcp/22"}, 22, 2375, 5432, 8080)
		n.port(8, 2375).Protocol, n.port(8, 2375).Probe, n.port(8, 2375).HTTPServer = "Docker API", "answered", "Docker/27.3.1 (linux)"
		if scanNo >= 4 {
			n.addPort(8, 6379, "Redis")
		}
		n.add(9, "3c:52:82:61:09:09", "HP Inc.", "HPLaserJet-M234", []string{"tcp/9100"}, 80, 443, 631, 9100)
		n.port(9, 443).TLSCommonName, n.port(9, 443).TLSIssuer = "HPLaserJet-M234", "HP Device CA"
		n.port(9, 443).TLSNotAfter = time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
		n.port(9, 443).TLSExpired = true
		if scanNo < 4 {
			n.port(9, 443).TLSNotAfter = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
		}
		n.add(10, "", "", "", []string{"tcp/80"}, 80)
		n.add(11, "a4:cf:12:3b:11:11", "Espressif Inc.", "", []string{"arp-cache"})
		if scanNo == 1 || scanNo == 3 {
			n.add(12, "3c:22:fb:88:12:12", "Apple, Inc.", "guest-macbook", []string{"tcp/22"}, 22, 88, 445, 5000)
		}
		if scanNo <= 2 {
			n.add(13, "70:ee:50:13:13:13", "Netatmo", "", []string{"tcp/80"}, 80)
		}
		// A camera whose Telnet answers once the firmware changes: acknowledged
		// after scan 3, reopened by scan 4.
		n.add(16, "9c:8e:cd:16:16:16", "Amcrest Technologies", "driveway-cam", []string{"tcp/554"}, 23, 80, 554, 8000)
		if scanNo >= 4 {
			n.port(16, 23).Protocol, n.port(16, 23).Probe, n.port(16, 23).Banner = "Telnet", "answered", "(none) login:"
		}
		// A Wi-Fi extender answering for two addresses.
		n.add(20, "b0:be:76:20:20:20", "TP-LINK TECHNOLOGIES CO.,LTD.", "extender", []string{"arp-cache"}, 80)
		n.add(21, "b0:be:76:20:20:20", "TP-LINK TECHNOLOGIES CO.,LTD.", "", []string{"arp-cache"})
		// Two machines answering for one address.
		if scanNo >= 3 {
			dup := n.add(30, "00:1e:06:30:30:30", "WIBRAIN", "", []string{"arp"}, 22)
			dup.DuplicateMACs = []string{"00:1e:06:30:30:30", "00:1e:06:30:30:31"}
		}
		n.add(40, "b8:27:eb:40:40:40", "Raspberry Pi Foundation", "pihole", []string{"tcp/53"}, 22, 53, 80, 443)
		n.add(41, "00:17:88:41:41:41", "Philips Lighting BV", "hue-bridge", []string{"tcp/80"}, 80, 443, 8080, 8443)
		n.add(42, "54:60:09:42:42:42", "Google, Inc.", "kitchen-speaker", []string{"tcp/8008"}, 8008, 8009, 8443, 9000)
		n.add(43, "44:65:0d:43:43:43", "Amazon Technologies Inc.", "echo-bedroom", []string{"tcp/443"}, 443, 4070, 8080, 55443)
		n.add(44, "d8:3a:dd:44:44:44", "Raspberry Pi Trading Ltd", "octoprint", []string{"tcp/80"}, 22, 80, 443, 5000)
		n.add(45, "94:e6:f7:45:45:45", "Intel Corporate", "media-pc", []string{"tcp/445"}, 139, 445, 3389, 32400)
		n.add(50, "dc:a6:32:5e:50:50", "Raspberry Pi Trading Ltd", "testbench", []string{"tcp/22"}, 22, 80, 443, 8080)
		n.add(60, "", "", "vpn-peer.example.net", []string{"tcp/443"}, 443)
		return n.done()
	}
	scans := []struct {
		id    string
		at    time.Time
		state string
		deep  bool
	}{
		{"s-home-1", time.Date(2026, 9, 20, 19, 30, 0, 0, time.UTC), "completed", false},
		{"s-home-2", time.Date(2026, 9, 24, 7, 55, 0, 0, time.UTC), "canceled", false},
		{"s-home-3", time.Date(2026, 9, 27, 21, 10, 0, 0, time.UTC), "completed", true},
		{"s-home-4", time.Date(2026, 9, 28, 8, 12, 0, 0, time.UTC), "completed", true},
	}
	var last *Snapshot
	for i, sc := range scans {
		home.deep = sc.deep
		snap := home.snapshot(sc.id, sc.at, sc.state, sc.state != "completed")
		snap.Hosts, snap.Ports = homeHosts(sc.at, i+1)
		if sc.state == "canceled" {
			// Stopped during the port phase: later hosts were never checked.
			snap.Hosts, snap.Ports = snap.Hosts[:6], snap.Ports[:6]
			snap.Warning += " The scan was stopped before it finished; these results are partial."
		}
		record(snap)
		switch i {
		case 0:
			if err := s.RenameProfile(snap.ProfileID, "Home"); err != nil {
				t.Fatal(err)
			}
			annotate(snap, "192.0.2.1", "Router", "", "core", "network")
			annotate(snap, "192.0.2.3", "NAS", "Nightly backups from both laptops. Admin page on :5001.", "backup", "storage")
			annotate(snap, "192.0.2.4", "This laptop", "", "wifi", "work")
			annotate(snap, "192.0.2.5", "Upstairs hallway access point, ceiling mount, PoE from switch port 7",
				"Replaced the old AP in March. Firmware updates are automatic.",
				"network", "wifi", "poe", "upstairs", "ceiling", "ubiquiti", "managed", "u6-lite", "second-floor", "installed-2026")
			annotate(snap, "192.0.2.7", "Old PC in the garage", "Kept for the lathe controller software. Do not update: the vendor's installer only runs on this build.\n\n"+
				"Telnet and FTP are how the lathe pulls its programs. Both are blocked at the router for everything outside the garage VLAN.\n\n"+
				"If it dies: the disk image is on the NAS under backups/garage-pc, and the licence dongle is in the drawer under the bench.", "garage", "legacy")
			annotate(snap, "192.0.2.8", "Dev box", "", "dev", "lab")
			annotate(snap, "192.0.2.9", "Printer", "", "office", "printer")
			annotate(snap, "192.0.2.12", "Guest laptop", "", "guest", "visitor")
			annotate(snap, "192.0.2.16", "Driveway camera", "", "camera", "outdoor")
			annotate(snap, "192.0.2.40", "Pi-hole", "", "dns", "network")
			annotate(snap, "192.0.2.41", "Hue bridge", "", "iot", "lights")
			annotate(snap, "192.0.2.42", "Kitchen speaker", "", "iot", "kitchen")
			annotate(snap, "192.0.2.43", "Bedroom Echo", "", "bedroom", "iot")
			annotate(snap, "192.0.2.44", "OctoPrint", "", "3d-printer", "lab")
			annotate(snap, "192.0.2.45", "Media PC", "", "living-room", "media")
			annotate(snap, "192.0.2.50", "Test bench Pi",
				"Draft checks: edit the name, tags or notes without saving, then let a scan finish, resize across 1200px, and switch to another device and back. The edits stay until Save or Discard; closing with edits pending asks first.",
				"lab", "test")
		case 2:
			annotate(snap, "192.0.2.6", "Phone", "", "family", "phone")
			ack(snap, "192.0.2.3", "smb-open/445", "Family file share; the NAS firewall allows only this network.")
			ack(snap, "192.0.2.16", "telnet-open/23", "Checked: Telnet is off in the camera settings.")
			ack(snap, "192.0.2.1", "tls-self-signed/443", "")
		case 3:
			annotate(snap, "192.0.2.2", "Living room TV", "", "living-room", "media")
		}
		last = snap
	}
	if s.CurrentProfile() != last.ProfileID {
		t.Fatal("home should be the current profile")
	}
	if st := s.Status(); st.LastError != "" {
		t.Fatal(st.LastError)
	}
}

// uiNetwork describes one synthetic network.
type uiNetwork struct {
	prefix string
	gwMAC  string
	deep   bool
}

func (n uiNetwork) snapshot(id string, at time.Time, state string, partial bool) *Snapshot {
	subnet := n.prefix + "0/24"
	methods := []string{"tcp", "arp-cache", "ports", "services", "names", "ssdp", "snmp"}
	if n.deep {
		methods = []string{"tcp", "icmp", "arp-sweep", "arp-cache", "ports", "services", "names", "ssdp", "snmp"}
	}
	elevated := n.deep
	return &Snapshot{
		ID: id, State: state, Partial: partial, FinishedAt: at,
		Coverage: Coverage{
			Ranges: []string{subnet}, Addresses: 254, Limit: 1024, Methods: methods, Deep: n.deep, Custom: true, Elevated: &elevated,
		},
		Targets: []string{subnet}, Deep: n.deep, CustomRange: true,
		GatewayIP: n.prefix + "1", GatewayMAC: n.gwMAC, GatewaySubnet: subnet,
		Warning: "In unprivileged mode, a host that does not accept connections on any discovery port appears only if it answered the OS's ARP lookup (arp-cache); hosts off the local segment will not appear at all.",
	}
}

func (n uiNetwork) hosts(at time.Time) *uiHosts {
	return &uiHosts{prefix: n.prefix, at: at, ports: map[string]*scan.Result{}}
}

// uiHosts collects one scan's hosts and open ports.
type uiHosts struct {
	prefix string
	at     time.Time
	hosts  []*discover.Host
	order  []string
	ports  map[string]*scan.Result
}

var uiServices = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 88: "Kerberos", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
	443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP", 1433: "MSSQL", 2375: "Docker", 2376: "Docker TLS", 3389: "RDP",
	4070: "Spotify", 5000: "HTTP-alt", 5001: "HTTPS-alt", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 7000: "AirPlay",
	8000: "HTTP-alt", 8001: "HTTP-alt", 8008: "HTTP-alt", 8009: "Cast", 8080: "HTTP-proxy", 8443: "HTTPS-alt", 9000: "HTTP-alt",
	9100: "JetDirect", 32400: "Plex", 55443: "HTTPS-alt",
}

func (u *uiHosts) add(last int, mac, vendor, hostname string, via []string, ports ...int) *discover.Host {
	ip := u.prefix + strconv.Itoa(last)
	h := &discover.Host{IP: ip, MAC: mac, Vendor: vendor, Hostname: hostname, AliveVia: via, LastSeen: u.at}
	u.hosts = append(u.hosts, h)
	u.order = append(u.order, ip)
	r := &scan.Result{IP: ip}
	for _, p := range ports {
		r.Ports = append(r.Ports, scan.OpenPort{Port: p, Service: uiServices[p]})
	}
	u.ports[ip] = r
	return h
}

func (u *uiHosts) addPort(last, port int, service string) {
	r := u.ports[u.prefix+strconv.Itoa(last)]
	r.Ports = append(r.Ports, scan.OpenPort{Port: port, Service: service})
}

func (u *uiHosts) host(last int) *discover.Host {
	for _, h := range u.hosts {
		if h.IP == u.prefix+strconv.Itoa(last) {
			return h
		}
	}
	panic("no host ." + strconv.Itoa(last))
}

func (u *uiHosts) port(last, port int) *scan.OpenPort {
	r := u.ports[u.prefix+strconv.Itoa(last)]
	for i := range r.Ports {
		if r.Ports[i].Port == port {
			return &r.Ports[i]
		}
	}
	panic("no port " + strconv.Itoa(port) + " on ." + strconv.Itoa(last))
}

func (u *uiHosts) done() ([]discover.Host, []scan.Result) {
	hosts := make([]discover.Host, 0, len(u.hosts))
	results := make([]scan.Result, 0, len(u.order))
	for i, h := range u.hosts {
		hosts = append(hosts, *h)
		results = append(results, *u.ports[u.order[i]])
	}
	return hosts, results
}
