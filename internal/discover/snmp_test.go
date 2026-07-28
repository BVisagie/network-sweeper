package discover

import (
	"testing"
)

func TestSNMPBuildAndParseRoundTrip(t *testing.T) {
	// Craft a minimal GetResponse with sysName and sysDescr octet strings.
	sysNameOID := encodeOID(oidSysName)
	sysDescrOID := encodeOID(oidSysDescr)
	vb1 := appendASNSeq(append(sysNameOID, encodeOctetString("switch-a")...))
	vb2 := appendASNSeq(append(sysDescrOID, encodeOctetString("Example Switch")...))
	pduBody := concat(
		encodeInteger(42),
		encodeInteger(0),
		encodeInteger(0),
		appendASNSeq(append(vb1, vb2...)),
	)
	pdu := encodeTLV(0xa2, pduBody)
	pkt := encodeTLV(0x30, concat(encodeInteger(1), encodeOctetString("public"), pdu))

	name, descr, ok := parseSNMPGetResponse(pkt, 42)
	if !ok {
		t.Fatal("parse failed")
	}
	if name != "switch-a" || descr != "Example Switch" {
		t.Fatalf("got name=%q descr=%q", name, descr)
	}

	req := buildSNMPv2cGet(42, "public", oidSysName, oidSysDescr)
	if len(req) < 40 || req[0] != 0x30 {
		t.Fatalf("bad request framing: %d bytes tag=%x", len(req), req[0])
	}
}

func TestEncodeDecodeOID(t *testing.T) {
	raw := encodeOID(oidSysName)
	tag, body, rest, ok := readTLV(raw)
	if !ok || tag != 0x06 || len(rest) != 0 {
		t.Fatalf("tlv %v %x", ok, tag)
	}
	if decodeOID(body) != "1.3.6.1.2.1.1.5.0" {
		t.Fatalf("got %s", decodeOID(body))
	}
}
