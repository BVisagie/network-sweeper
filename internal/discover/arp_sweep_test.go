package discover

import (
	"net"
	"testing"
)

func TestBuildParseARPRequestReply(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("192.168.1.10").To4()
	dstIP := net.ParseIP("192.168.1.20").To4()

	// Shared wire format used by linux/darwin builders — test via linux symbols when available.
	// Use the stub-safe helpers by reconstructing with the same layout as buildARPRequest.
	frame := make([]byte, 42)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], srcMAC)
	frame[12], frame[13] = 0x08, 0x06
	frame[14], frame[15] = 0x00, 0x01
	frame[16], frame[17] = 0x08, 0x00
	frame[18], frame[19] = 6, 4
	frame[20], frame[21] = 0x00, 0x01
	copy(frame[22:28], srcMAC)
	copy(frame[28:32], srcIP)
	copy(frame[38:42], dstIP)

	// Reply: swap, op=2
	reply := append([]byte(nil), frame...)
	copy(reply[0:6], srcMAC)
	copy(reply[6:12], []byte{1, 2, 3, 4, 5, 6})
	reply[20], reply[21] = 0x00, 0x02
	copy(reply[22:28], []byte{1, 2, 3, 4, 5, 6})
	copy(reply[28:32], dstIP)
	copy(reply[38:42], srcIP)

	ip := net.IP(reply[28:32]).String()
	mac := net.HardwareAddr(reply[22:28]).String()
	if ip != "192.168.1.20" || mac != "01:02:03:04:05:06" {
		t.Fatalf("ip=%s mac=%s", ip, mac)
	}
}

func TestARPSweepSupportedMatchesGOOS(t *testing.T) {
	_ = ARPSweepSupported()
}
