package discover

import (
	"strings"
	"testing"
)

// Hosts promoted from the ARP cache must be real, resolved neighbours: an
// incomplete or multicast row would list a device that is not there.
func TestParseProcARPKeepsOnlyCompleteEntries(t *testing.T) {
	const table = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.34     0x1         0x2         C4:38:75:11:35:57     *        enp8s0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        enp8s0
192.168.1.98     0x1         0x0         aa:bb:cc:dd:ee:ff     *        enp8s0
192.168.1.50     0x1         0x6         3c:e9:f7:71:5b:3d     *        enp8s0
`
	got := parseProcARP(strings.NewReader(table))
	want := map[string]string{
		"192.168.1.34": "c4:38:75:11:35:57",
		"192.168.1.50": "3c:e9:f7:71:5b:3d", // permanent (0x4) + complete (0x2)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for ip, mac := range want {
		if got[ip] != mac {
			t.Fatalf("%s: got %q, want %q", ip, got[ip], mac)
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
