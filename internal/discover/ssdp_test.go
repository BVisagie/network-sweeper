package discover

import (
	"testing"
)

func TestParseSSDPLocation(t *testing.T) {
	msg := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=100\r\nLOCATION: http://192.168.1.5:1400/xml/device_description.xml\r\nST: upnp:rootdevice\r\n\r\n"
	got := parseSSDPLocation(msg)
	if got != "http://192.168.1.5:1400/xml/device_description.xml" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractXMLTagFriendlyName(t *testing.T) {
	xml := `<?xml version="1.0"?><root><device><friendlyName>Sonos Beam</friendlyName></device></root>`
	got := extractXMLTag(xml, "friendlyName")
	if got != "Sonos Beam" {
		t.Fatalf("got %q", got)
	}
}

func TestSetHostnameIfEmpty(t *testing.T) {
	h := Host{Hostname: "keep.me"}
	setHostnameIfEmpty(&h, "new")
	if h.Hostname != "keep.me" {
		t.Fatal("overwrote")
	}
	h2 := Host{}
	setHostnameIfEmpty(&h2, "  printer.local. ")
	if h2.Hostname != "printer.local" {
		t.Fatalf("got %q", h2.Hostname)
	}
}
