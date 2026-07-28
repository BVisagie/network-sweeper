package discover

import (
	"encoding/binary"
	"testing"
)

func TestParseMDNSPTRAnswers(t *testing.T) {
	// Build a synthetic response: PTR for 1.0.0.10.in-addr.arpa -> LivingRoom.local
	owner := encodeDNSName("1.0.0.10.in-addr.arpa")
	ptr := encodeDNSName("LivingRoom.local")
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[2:4], 0x8400)
	binary.BigEndian.PutUint16(pkt[6:8], 1) // one answer
	pkt = append(pkt, owner...)
	rr := make([]byte, 10)
	binary.BigEndian.PutUint16(rr[0:2], 12) // PTR
	binary.BigEndian.PutUint16(rr[2:4], 1)
	binary.BigEndian.PutUint16(rr[8:10], uint16(len(ptr)))
	pkt = append(pkt, rr...)
	pkt = append(pkt, ptr...)

	got := parseMDNSPTRAnswers(pkt)
	if got["10.0.0.1"] != "LivingRoom" {
		t.Fatalf("got %#v", got)
	}
}

func TestReverseARPA(t *testing.T) {
	if reverseARPA("192.168.1.50") != "50.1.168.192.in-addr.arpa" {
		t.Fatal(reverseARPA("192.168.1.50"))
	}
}

func TestArpaToIP(t *testing.T) {
	if arpaToIP("50.1.168.192.in-addr.arpa") != "192.168.1.50" {
		t.Fatal(arpaToIP("50.1.168.192.in-addr.arpa"))
	}
}
