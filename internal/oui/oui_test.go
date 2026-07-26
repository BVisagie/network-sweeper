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
