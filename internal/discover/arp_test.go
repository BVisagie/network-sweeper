package discover

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Hosts promoted from the ARP cache must be real, resolved neighbours the OS
// just asked the network about: not incomplete rows, not static mappings
// (used without any ARP exchange), not multicast, not outside the targets.
func TestPromoteARPCacheOnlyFreshUnicastTargets(t *testing.T) {
	linux := parseProcARP(strings.NewReader(`IP address       HW type     Flags       HW address            Mask     Device
192.168.1.34     0x1         0x2         C4:38:75:11:35:57     *        enp8s0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        enp8s0
192.168.1.50     0x1         0x6         3c:e9:f7:71:5b:3d     *        enp8s0
192.168.1.60     0x1         0x2         01:00:5e:00:00:fb     *        enp8s0
10.9.9.9         0x1         0x2         3c:e9:f7:71:5b:3e     *        enp8s0
`))
	if e := linux["192.168.1.50"]; !e.Static || e.MAC != "3c:e9:f7:71:5b:3d" {
		t.Fatalf("permanent row: got %+v, want static with its MAC kept for enrichment", e)
	}
	if _, ok := linux["192.168.1.99"]; ok {
		t.Fatal("incomplete row should be skipped")
	}

	mac := parseARPCommand(`? (192.168.1.70) at a4:5e:60:e8:1:2d on en0 ifscope [ethernet]
? (192.168.1.71) at 0:11:22:33:44:55 on en0 permanent [ethernet]`)
	win := parseARPCommand(`  192.168.1.80          aa-bb-cc-dd-ee-01     dynamic
  192.168.1.81          aa-bb-cc-dd-ee-02     static
  224.0.0.251           01-00-5e-00-00-fb     static`)

	table := map[string]arpEntry{}
	for _, m := range []map[string]arpEntry{linux, mac, win} {
		for ip, e := range m {
			table[ip] = e
		}
	}
	enumerated := map[string]bool{}
	for _, ip := range []string{"192.168.1.34", "192.168.1.50", "192.168.1.60", "192.168.1.70", "192.168.1.71", "192.168.1.80", "192.168.1.81"} {
		enumerated[ip] = true
	}
	alive := map[string]*Host{}
	promoteARPCache(alive, table, enumerated)

	want := map[string]string{
		"192.168.1.34": "c4:38:75:11:35:57",
		"192.168.1.70": "a4:5e:60:e8:01:2d",
		"192.168.1.80": "aa:bb:cc:dd:ee:01",
	}
	if len(alive) != len(want) {
		t.Fatalf("promoted %d hosts, want %d: %v", len(alive), len(want), alive)
	}
	for ip, m := range want {
		if h := alive[ip]; h == nil || h.MAC != m || h.AliveVia[0] != "arp-cache" {
			t.Fatalf("%s: got %+v, want arp-cache host with MAC %s", ip, h, m)
		}
	}
}

func TestUnicastMAC(t *testing.T) {
	for mac, want := range map[string]bool{
		"c4:38:75:11:35:57": true,
		"86:f1:bd:6f:77:1d": true,  // locally administered is still unicast
		"01:00:5e:00:00:fb": false, // IPv4 multicast (Windows arp -a static rows)
		"33:33:00:00:00:01": false, // IPv6 multicast
		"ff:ff:ff:ff:ff:ff": false,
		"00:00:00:00:00:00": false,
		"not-a-mac":         false,
	} {
		if got := unicastMAC(mac); got != want {
			t.Errorf("unicastMAC(%q) = %v, want %v", mac, got, want)
		}
	}
}

// One BPF read can carry several records; a duplicate IP is two ARP replies,
// often in the same read, so every record must reach the parser.
func TestEachBPFRecordWalksEveryRecord(t *testing.T) {
	record := func(senderMAC byte) []byte {
		frame := make([]byte, 42) // ARP reply: sender MAC at 22:28
		frame[27] = senderMAC
		hdr := make([]byte, 20) // sizeof(struct bpf_hdr) on Darwin
		binary.NativeEndian.PutUint32(hdr[8:], uint32(len(frame)))
		binary.NativeEndian.PutUint32(hdr[12:], uint32(len(frame)))
		binary.NativeEndian.PutUint16(hdr[16:], uint16(len(hdr)))
		rec := append(hdr, frame...)
		return append(rec, make([]byte, (4-len(rec)%4)%4)...) // BPF_WORDALIGN padding
	}
	buf := append(record(0x01), record(0x02)...)
	buf = append(buf, record(0x03)[:30]...) // truncated trailing record

	var senders []byte
	eachBPFRecord(buf, func(frame []byte) {
		if len(frame) != 42 {
			t.Fatalf("frame length %d, want 42", len(frame))
		}
		senders = append(senders, frame[27])
	})
	if string(senders) != "\x01\x02" {
		t.Fatalf("got senders %x, want 0102", senders)
	}
}
