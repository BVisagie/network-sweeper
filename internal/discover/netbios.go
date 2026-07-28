package discover

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	nbnsPort       = "137"
	nbstatType     = 0x0021
	nbClassIN      = 0x0001
	nbNameEntryLen = 18
)

// FillEmptyHostnames runs NetBIOS node-status (NBSTAT) queries for hosts with
// an empty Hostname. Existing names (e.g. reverse DNS) are never overwritten.
func FillEmptyHostnames(ctx context.Context, hosts []Host, timeout time.Duration, concurrency int) {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var trx atomic.Uint32
	for i := range hosts {
		if hosts[i].Hostname != "" {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			id := uint16(trx.Add(1))
			if name := queryNetBIOSName(ctx, hosts[i].IP, timeout, id); name != "" {
				hosts[i].Hostname = name
			}
		}()
	}
	wg.Wait()
}

func queryNetBIOSName(ctx context.Context, ip string, timeout time.Duration, trxID uint16) string {
	if ctx.Err() != nil {
		return ""
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, nbnsPort))
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	req := buildNBStatQuery(trxID)
	if _, err := conn.Write(req); err != nil {
		return ""
	}
	buf := make([]byte, 576)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return parseNBStatHostname(buf[:n], trxID)
}

func buildNBStatQuery(trxID uint16) []byte {
	// Header + encoded "*" name + NBSTAT/IN question.
	name := make([]byte, 16)
	name[0] = '*'
	encoded := encodeNetBIOSName(name)

	pkt := make([]byte, 0, 12+len(encoded)+4)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], trxID)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0000) // standard query
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // questions
	pkt = append(pkt, hdr...)
	pkt = append(pkt, encoded...)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], nbstatType)
	binary.BigEndian.PutUint16(q[2:4], nbClassIN)
	pkt = append(pkt, q...)
	return pkt
}

// encodeNetBIOSName first-level-encodes a 16-byte NetBIOS name into a DNS label.
func encodeNetBIOSName(name16 []byte) []byte {
	if len(name16) != 16 {
		panic("netbios name must be 16 bytes")
	}
	out := make([]byte, 34)
	out[0] = 32
	for i := 0; i < 16; i++ {
		c := name16[i]
		out[1+2*i] = 'A' + (c >> 4)
		out[2+2*i] = 'A' + (c & 0x0f)
	}
	out[33] = 0
	return out
}

func parseNBStatHostname(pkt []byte, wantTrx uint16) string {
	if len(pkt) < 12 {
		return ""
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != wantTrx {
		return ""
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 == 0 {
		return "" // not a response
	}
	questions := binary.BigEndian.Uint16(pkt[4:6])
	answers := binary.BigEndian.Uint16(pkt[6:8])
	if answers == 0 {
		return ""
	}
	off := 12
	for i := 0; i < int(questions); i++ {
		var ok bool
		off, ok = skipDNSName(pkt, off)
		if !ok || off+4 > len(pkt) {
			return ""
		}
		off += 4 // type + class
	}
	for a := 0; a < int(answers); a++ {
		var ok bool
		off, ok = skipDNSName(pkt, off)
		if !ok || off+10 > len(pkt) {
			return ""
		}
		rrType := binary.BigEndian.Uint16(pkt[off : off+2])
		// class at off+2, TTL at off+4
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if off+rdlen > len(pkt) {
			return ""
		}
		rdata := pkt[off : off+rdlen]
		off += rdlen
		if rrType != nbstatType {
			continue
		}
		if name := pickNetBIOSName(rdata); name != "" {
			return name
		}
	}
	return ""
}

func skipDNSName(pkt []byte, off int) (int, bool) {
	for {
		if off >= len(pkt) {
			return 0, false
		}
		l := int(pkt[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xc0 == 0xc0 { // pointer compression
			if off+2 > len(pkt) {
				return 0, false
			}
			return off + 2, true
		}
		if l&0xc0 != 0 {
			return 0, false
		}
		off += 1 + l
	}
}

func pickNetBIOSName(rdata []byte) string {
	if len(rdata) < 1 {
		return ""
	}
	n := int(rdata[0])
	need := 1 + n*nbNameEntryLen
	if len(rdata) < need {
		return ""
	}
	var (
		best     string
		bestRank int // higher is better; 0 = none
	)
	for i := 0; i < n; i++ {
		entry := rdata[1+i*nbNameEntryLen : 1+(i+1)*nbNameEntryLen]
		raw := entry[:15]
		suffix := entry[15]
		flags := binary.BigEndian.Uint16(entry[16:18])
		if flags&0x8000 != 0 {
			continue // group name
		}
		name := sanitizeHostname(string(raw))
		if name == "" || isJunkNetBIOSName(name) {
			continue
		}
		rank := 1
		switch suffix {
		case 0x00:
			rank = 3
		case 0x20:
			rank = 2
		}
		if rank > bestRank {
			bestRank = rank
			best = name
		}
	}
	return best
}

func isJunkNetBIOSName(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "__MSBROWSE__", "WORKGROUP", "HOME", "MSHOME", "LOCAL":
		return true
	}
	return false
}
