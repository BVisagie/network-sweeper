package oui

import "testing"

func TestLookup(t *testing.T) {
	if Lookup("b8:27:eb:11:22:33") != "Raspberry Pi Foundation" {
		t.Fatalf("got %q", Lookup("b8:27:eb:11:22:33"))
	}
	if Lookup("00-0c-29-aa-bb-cc") != "VMware" {
		t.Fatalf("got %q", Lookup("00-0c-29-aa-bb-cc"))
	}
	if Lookup("a0:42:46:11:22:33") != "Netgear" {
		t.Fatalf("got %q", Lookup("a0:42:46:11:22:33"))
	}
	if Lookup("ff:ff:ff:ff:ff:ff") != "" {
		t.Fatal("expected empty for unknown")
	}
}

// The embedded IEEE registry backs every lookup the curated map misses; a
// broken or truncated regeneration would silently blank the Vendor column.
func TestIEEEFallback(t *testing.T) {
	if n := len(ieeeTable()); n < 30000 {
		t.Fatalf("embedded registry has %d prefixes, want the full MA-L list", n)
	}
	if got := Lookup("c4:38:75:11:35:57"); got != "Sonos, Inc." { // quoted in the CSV
		t.Fatalf("got %q", got)
	}
	if got := Lookup("b8:27:eb:11:22:33"); got != "Raspberry Pi Foundation" { // curated wins
		t.Fatalf("got %q", got)
	}
}

func TestLocallyAdministered(t *testing.T) {
	if !LocallyAdministered("86:f1:bd:6f:77:1d") || !LocallyAdministered("DA-7F-30-AE-E6-AE") {
		t.Fatal("U/L bit set: want locally administered")
	}
	if LocallyAdministered("c4:38:75:11:35:57") || LocallyAdministered("") {
		t.Fatal("U/L bit clear or empty: want false")
	}
}
