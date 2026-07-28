package discover

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEncodeNetBIOSName(t *testing.T) {
	name := make([]byte, 16)
	name[0] = '*'
	enc := encodeNetBIOSName(name)
	if len(enc) != 34 || enc[0] != 32 || enc[33] != 0 {
		t.Fatalf("bad framing: len=%d first=%d last=%d", len(enc), enc[0], enc[33])
	}
	// '*' = 0x2A → 'A'+2, 'A'+10 → 'C','K'
	if enc[1] != 'C' || enc[2] != 'K' {
		t.Fatalf("star encode got %q%q", enc[1], enc[2])
	}
	// null → 'A','A'
	if enc[3] != 'A' || enc[4] != 'A' {
		t.Fatalf("pad encode got %q%q", enc[3], enc[4])
	}
}

func TestBuildNBStatQuery(t *testing.T) {
	pkt := buildNBStatQuery(0x1234)
	if len(pkt) < 50 {
		t.Fatalf("short packet %d", len(pkt))
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != 0x1234 {
		t.Fatal("trx id")
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != 1 {
		t.Fatal("questions")
	}
	// type/class at end
	typ := binary.BigEndian.Uint16(pkt[len(pkt)-4 : len(pkt)-2])
	class := binary.BigEndian.Uint16(pkt[len(pkt)-2:])
	if typ != nbstatType || class != nbClassIN {
		t.Fatalf("type/class %04x/%04x", typ, class)
	}
}

func TestParseNBStatHostname(t *testing.T) {
	const trx = uint16(0xabcd)
	pkt := craftNBStatResponse(t, trx, []nbName{
		{name: "WORKGROUP      ", suffix: 0x00, group: true},
		{name: "DESKTOP-ABC123 ", suffix: 0x00, group: false},
		{name: "DESKTOP-ABC123 ", suffix: 0x20, group: false},
	})
	got := parseNBStatHostname(pkt, trx)
	if got != "DESKTOP-ABC123" {
		t.Fatalf("got %q", got)
	}
}

func TestParseNBStatHostnamePrefersWorkstationSuffix(t *testing.T) {
	const trx = uint16(1)
	pkt := craftNBStatResponse(t, trx, []nbName{
		{name: "FILESERVER     ", suffix: 0x20, group: false},
		{name: "PCNAME         ", suffix: 0x00, group: false},
	})
	got := parseNBStatHostname(pkt, trx)
	if got != "PCNAME" {
		t.Fatalf("got %q want PCNAME", got)
	}
}

func TestParseNBStatWrongTrx(t *testing.T) {
	pkt := craftNBStatResponse(t, 1, []nbName{{name: "HOST           ", suffix: 0x00, group: false}})
	if parseNBStatHostname(pkt, 2) != "" {
		t.Fatal("expected empty on trx mismatch")
	}
}

func TestSanitizeHostname(t *testing.T) {
	if got := sanitizeHostname("  FOO.BAR.  "); got != "FOO.BAR" {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeHostname("bad\nname"); got != "bad" {
		t.Fatalf("got %q", got)
	}
	if sanitizeHostname("   ") != "" {
		t.Fatal("spaces should be empty")
	}
	if got := sanitizeHostname(`32&quot; TV`); got != `32" TV` {
		t.Fatalf("entities: %q", got)
	}
}

func TestFillEmptyHostnamesPreservesExisting(t *testing.T) {
	hosts := []Host{
		{IP: "127.0.0.1", Hostname: "already.local"},
		{IP: "127.0.0.1"}, // will query localhost:137; likely empty — just ensure no panic / overwrite path
	}
	FillEmptyHostnames(context.Background(), hosts, 50*time.Millisecond, 2)
	if hosts[0].Hostname != "already.local" {
		t.Fatalf("overwrote reverse DNS: %q", hosts[0].Hostname)
	}
}

func TestFillEmptyHostnamesCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hosts := []Host{{IP: "10.255.255.1"}, {IP: "10.255.255.2"}}
	FillEmptyHostnames(ctx, hosts, time.Second, 2)
	if hosts[0].Hostname != "" || hosts[1].Hostname != "" {
		t.Fatal("canceled fill should not set names")
	}
}

func TestQueryNetBIOSNameAgainstMock(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 576)
		n, remote, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		trx := binary.BigEndian.Uint16(buf[0:2])
		resp := craftNBStatResponse(t, trx, []nbName{
			{name: "MOCKHOST       ", suffix: 0x00, group: false},
		})
		_, _ = pc.WriteTo(resp, remote)
	}()

	// Dial the mock by temporarily using its port — queryNetBIOSName always uses 137.
	// Exercise parse via a one-shot dial to the mock instead.
	ctx := context.Background()
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	req := buildNBStatQuery(0x42)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 576)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := parseNBStatHostname(buf[:n], 0x42)
	if got != "MOCKHOST" {
		t.Fatalf("got %q", got)
	}
}

type nbName struct {
	name   string // 15 chars
	suffix byte
	group  bool
}

func craftNBStatResponse(t *testing.T, trx uint16, names []nbName) []byte {
	t.Helper()
	name := make([]byte, 16)
	name[0] = '*'
	enc := encodeNetBIOSName(name)

	rdata := make([]byte, 1+len(names)*nbNameEntryLen)
	rdata[0] = byte(len(names))
	for i, n := range names {
		raw := []byte(n.name)
		if len(raw) != 15 {
			t.Fatalf("name %q must be 15 bytes, got %d", n.name, len(raw))
		}
		off := 1 + i*nbNameEntryLen
		copy(rdata[off:off+15], raw)
		rdata[off+15] = n.suffix
		flags := uint16(0)
		if n.group {
			flags |= 0x8000
		}
		binary.BigEndian.PutUint16(rdata[off+16:off+18], flags)
	}

	pkt := make([]byte, 0, 12+len(enc)+4+2+2+4+2+len(rdata))
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], trx)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // question
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // answer
	pkt = append(pkt, hdr...)
	pkt = append(pkt, enc...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], nbstatType)
	binary.BigEndian.PutUint16(q[2:4], nbClassIN)
	pkt = append(pkt, q...)

	// Answer: pointer to question name at offset 12
	pkt = append(pkt, 0xc0, 0x0c)
	ans := make([]byte, 10)
	binary.BigEndian.PutUint16(ans[0:2], nbstatType)
	binary.BigEndian.PutUint16(ans[2:4], nbClassIN)
	binary.BigEndian.PutUint32(ans[4:8], 0) // TTL
	binary.BigEndian.PutUint16(ans[8:10], uint16(len(rdata)))
	pkt = append(pkt, ans...)
	pkt = append(pkt, rdata...)
	return pkt
}
