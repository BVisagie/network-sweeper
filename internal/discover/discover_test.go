package discover

import (
	"strings"
	"testing"
)

func TestParseARPLinuxSample(t *testing.T) {
	sample := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0
`
	out := map[string]string{}
	first := true
	for _, line := range strings.Split(sample, "\n") {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip, mac := fields[0], fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		out[ip] = strings.ToLower(mac)
	}
	if out["192.168.1.1"] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("got %#v", out)
	}
	if _, ok := out["192.168.1.2"]; ok {
		t.Fatal("incomplete entry should be skipped")
	}
}

func TestLooksLikeMAC(t *testing.T) {
	if !looksLikeMAC("aa:bb:cc:dd:ee:ff") {
		t.Fatal("expected mac")
	}
	if looksLikeMAC("aa:bb:cc") {
		t.Fatal("short should fail")
	}
}

func TestIPLess(t *testing.T) {
	if !ipLess("10.0.0.1", "10.0.0.2") {
		t.Fatal("ordering")
	}
	if ipLess("10.0.0.2", "10.0.0.1") {
		t.Fatal("ordering")
	}
}
