package discover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const mdnsPort = 5353

var mdnsGroup = net.ParseIP("224.0.0.251")

// fillEmptyHostnamesMDNS sends reverse-PTR mDNS queries and listens for a short window.
func fillEmptyHostnamesMDNS(ctx context.Context, hosts []Host, window time.Duration) {
	if window <= 0 {
		window = 1500 * time.Millisecond
	}
	need := map[string]int{} // ip -> index
	for i := range hosts {
		if hosts[i].Hostname == "" {
			need[hosts[i].IP] = i
		}
	}
	if len(need) == 0 || ctx.Err() != nil {
		return
	}

	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return
	}
	defer pc.Close()

	deadline := time.Now().Add(window)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = pc.SetDeadline(deadline)

	dst := &net.UDPAddr{IP: mdnsGroup, Port: mdnsPort}
	trx := uint16(1)
	for ip := range need {
		if ctx.Err() != nil {
			return
		}
		_, _ = pc.WriteTo(buildMDNSReversePTR(trx, ip), dst)
		trx++
	}

	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		for ip, name := range parseMDNSPTRAnswers(buf[:n]) {
			idx, ok := need[ip]
			if !ok {
				continue
			}
			setHostnameIfEmpty(&hosts[idx], name)
			if hosts[idx].Hostname != "" {
				delete(need, ip)
			}
		}
		if len(need) == 0 {
			return
		}
	}
}

func buildMDNSReversePTR(trx uint16, ip string) []byte {
	nameWire := encodeDNSName(reverseARPA(ip))
	pkt := make([]byte, 12+len(nameWire)+4)
	binary.BigEndian.PutUint16(pkt[0:2], trx)
	binary.BigEndian.PutUint16(pkt[4:6], 1) // questions
	copy(pkt[12:], nameWire)
	off := 12 + len(nameWire)
	binary.BigEndian.PutUint16(pkt[off:off+2], 12) // PTR
	binary.BigEndian.PutUint16(pkt[off+2:off+4], 1) // IN
	return pkt
}

func reverseARPA(ip string) string {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0])
}

func encodeDNSName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	parts := strings.Split(name, ".")
	var out []byte
	for _, p := range parts {
		if p == "" {
			continue
		}
		if len(p) > 63 {
			p = p[:63]
		}
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	out = append(out, 0)
	return out
}

// parseMDNSPTRAnswers returns map[ip]hostname from PTR answers in a DNS/mDNS packet.
func parseMDNSPTRAnswers(pkt []byte) map[string]string {
	out := map[string]string{}
	if len(pkt) < 12 {
		return out
	}
	if binary.BigEndian.Uint16(pkt[2:4])&0x8000 == 0 {
		return out
	}
	questions := int(binary.BigEndian.Uint16(pkt[4:6]))
	answers := int(binary.BigEndian.Uint16(pkt[6:8]))
	authority := int(binary.BigEndian.Uint16(pkt[8:10]))
	additional := int(binary.BigEndian.Uint16(pkt[10:12]))
	off := 12
	var ok bool
	for i := 0; i < questions; i++ {
		off, ok = skipDNSName(pkt, off)
		if !ok || off+4 > len(pkt) {
			return out
		}
		off += 4
	}
	rrCount := answers + authority + additional
	for i := 0; i < rrCount; i++ {
		var owner string
		owner, off, ok = readDNSName(pkt, off)
		if !ok || off+10 > len(pkt) {
			return out
		}
		rrType := binary.BigEndian.Uint16(pkt[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if rdlen < 0 || off+rdlen > len(pkt) {
			return out
		}
		rdataOff := off
		off += rdlen
		if rrType != 12 {
			continue
		}
		ptr, _, ok := readDNSName(pkt, rdataOff)
		if !ok {
			continue
		}
		ip := arpaToIP(owner)
		if ip == "" {
			continue
		}
		hn := sanitizeHostname(strings.TrimSuffix(ptr, ".local"))
		if hn == "" {
			hn = sanitizeHostname(ptr)
		}
		if hn != "" {
			out[ip] = hn
		}
	}
	return out
}

func readDNSName(pkt []byte, off int) (string, int, bool) {
	var parts []string
	next := off
	jumped := false
	for hops := 0; hops < 32; hops++ {
		if off >= len(pkt) {
			return "", 0, false
		}
		l := int(pkt[off])
		if l == 0 {
			if !jumped {
				next = off + 1
			}
			return strings.Join(parts, "."), next, true
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(pkt) {
				return "", 0, false
			}
			if !jumped {
				next = off + 2
				jumped = true
			}
			off = int(binary.BigEndian.Uint16(pkt[off:off+2]) & 0x3fff)
			continue
		}
		if l&0xc0 != 0 || off+1+l > len(pkt) {
			return "", 0, false
		}
		parts = append(parts, string(pkt[off+1:off+1+l]))
		off += 1 + l
	}
	return "", 0, false
}

func arpaToIP(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	const suf = ".in-addr.arpa"
	if !strings.HasSuffix(name, suf) {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(name, suf), ".")
	if len(parts) != 4 {
		return ""
	}
	ip := net.ParseIP(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
}

// EnrichHostnames fills empty Hostname via NetBIOS then mDNS (never overwrites).
func EnrichHostnames(ctx context.Context, hosts []Host, nbTimeout time.Duration, concurrency int, mdnsWindow time.Duration) {
	FillEmptyHostnames(ctx, hosts, nbTimeout, concurrency)
	fillEmptyHostnamesMDNS(ctx, hosts, mdnsWindow)
}
