package discover

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// OID sysName.0 and sysDescr.0
var (
	oidSysDescr = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysName  = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
)

// ProbeSNMP tries a single SNMPv2c GET with community "public" on UDP/161.
// On success: marks SNMPPublic, stores sysDescr, fills empty Hostname from sysName.
func ProbeSNMP(ctx context.Context, hosts []Host, timeout time.Duration, concurrency int) {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range hosts {
		if ctx.Err() != nil {
			break
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
			sysName, sysDescr, ok := snmpPublicGet(ctx, hosts[i].IP, timeout)
			if !ok {
				return
			}
			hosts[i].SNMPPublic = true
			if d := sanitizeHostname(sysDescr); d != "" {
				if len(d) > 120 {
					d = d[:120]
				}
				hosts[i].SNMPSysDescr = d
			}
			setHostnameIfEmpty(&hosts[i], sysName)
		}()
	}
	wg.Wait()
}

func snmpPublicGet(ctx context.Context, ip string, timeout time.Duration) (sysName, sysDescr string, ok bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "161"))
	if err != nil {
		return "", "", false
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	reqID := int32(time.Now().UnixNano() & 0x7fffffff)
	req := buildSNMPv2cGet(reqID, "public", oidSysName, oidSysDescr)
	if _, err := conn.Write(req); err != nil {
		return "", "", false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", "", false
	}
	return parseSNMPGetResponse(buf[:n], reqID)
}

func buildSNMPv2cGet(reqID int32, community string, oids ...[]int) []byte {
	var varbind []byte
	for _, oid := range oids {
		vb := appendASNSeq(append(encodeOID(oid), encodeNull()...))
		varbind = append(varbind, vb...)
	}
	pduBody := concat(
		encodeInteger(int64(reqID)),
		encodeInteger(0), // error-status
		encodeInteger(0), // error-index
		appendASNSeq(varbind),
	)
	pdu := encodeTLV(0xa0, pduBody) // GetRequest
	body := concat(
		encodeInteger(1), // version SNMPv2c
		encodeOctetString(community),
		pdu,
	)
	return encodeTLV(0x30, body)
}

func parseSNMPGetResponse(pkt []byte, _ int32) (sysName, sysDescr string, ok bool) {
	vals, _, errOK := decodeSNMPResponse(pkt)
	if !errOK || len(vals) == 0 {
		return "", "", false
	}
	for oid, val := range vals {
		switch oid {
		case "1.3.6.1.2.1.1.5.0":
			sysName = val
		case "1.3.6.1.2.1.1.1.0":
			sysDescr = val
		}
	}
	return sysName, sysDescr, true
}

func decodeSNMPResponse(pkt []byte) (map[string]string, int32, bool) {
	out := map[string]string{}
	tag, content, rest, ok := readTLV(pkt)
	if !ok || tag != 0x30 || len(rest) != 0 && false {
		_ = rest
	}
	if !ok || tag != 0x30 {
		return out, 0, false
	}
	// version
	_, content, ok = readTLVExpect(content, 0x02)
	if !ok {
		return out, 0, false
	}
	// community
	_, content, ok = readTLVExpect(content, 0x04)
	if !ok {
		return out, 0, false
	}
	// PDU (GetResponse 0xa2 or Report etc.)
	pduTag, pdu, _, ok := readTLV(content)
	if !ok || (pduTag != 0xa2 && pduTag != 0xa0 && pduTag != 0xa1) {
		return out, 0, false
	}
	reqTLV, pdu, ok := readTLVExpect(pdu, 0x02)
	if !ok {
		return out, 0, false
	}
	reqID := int32(decodeASNInt(reqTLV))
	// error-status, error-index
	_, pdu, ok = readTLVExpect(pdu, 0x02)
	if !ok {
		return out, reqID, false
	}
	_, pdu, ok = readTLVExpect(pdu, 0x02)
	if !ok {
		return out, reqID, false
	}
	vblist, _, ok := readTLVExpect(pdu, 0x30)
	if !ok {
		return out, reqID, false
	}
	for len(vblist) > 0 {
		var vb []byte
		vb, vblist, ok = readTLVExpect(vblist, 0x30)
		if !ok {
			break
		}
		oidBytes, vb, ok := readTLVExpect(vb, 0x06)
		if !ok {
			break
		}
		oid := decodeOID(oidBytes)
		valTag, val, _, ok := readTLV(vb)
		if !ok {
			break
		}
		if valTag == 0x04 || valTag == 0x44 { // octet string / opaque
			out[oid] = string(val)
		}
	}
	return out, reqID, true
}

func encodeOID(oids []int) []byte {
	if len(oids) < 2 {
		return encodeTLV(0x06, nil)
	}
	body := []byte{byte(oids[0]*40 + oids[1])}
	for _, n := range oids[2:] {
		body = append(body, encodeBase128(n)...)
	}
	return encodeTLV(0x06, body)
}

func decodeOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first := int(b[0])
	parts := []int{first / 40, first % 40}
	var v int
	for i := 1; i < len(b); i++ {
		v = (v << 7) | int(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			parts = append(parts, v)
			v = 0
		}
	}
	var s string
	for i, p := range parts {
		if i > 0 {
			s += "."
		}
		s += itoa(p)
	}
	return s
}

func encodeBase128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0x7f)}, tmp...)
		n >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

func encodeInteger(v int64) []byte {
	var body []byte
	if v == 0 {
		body = []byte{0}
	} else {
		neg := v < 0
		u := uint64(v)
		if neg {
			u = uint64(^v)
		}
		for u > 0 {
			body = append([]byte{byte(u)}, body...)
			u >>= 8
		}
		if neg {
			for i := range body {
				body[i] = ^body[i]
			}
			// ensure sign bit
			if body[0]&0x80 == 0 {
				body = append([]byte{0xff}, body...)
			}
		} else if body[0]&0x80 != 0 {
			body = append([]byte{0x00}, body...)
		}
	}
	return encodeTLV(0x02, body)
}

func decodeASNInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	for _, c := range b {
		v = (v << 8) | int64(c)
	}
	// sign extend if negative
	if b[0]&0x80 != 0 && len(b) < 8 {
		for i := len(b); i < 8; i++ {
			v |= int64(0xff) << (8 * (7 - (i - (8 - len(b)))))
		}
		// simpler:
		shift := uint(64 - 8*len(b))
		v = (v << shift) >> shift
	}
	return v
}

func encodeOctetString(s string) []byte {
	return encodeTLV(0x04, []byte(s))
}

func encodeNull() []byte {
	return []byte{0x05, 0x00}
}

func appendASNSeq(body []byte) []byte {
	return encodeTLV(0x30, body)
}

func encodeTLV(tag byte, body []byte) []byte {
	n := len(body)
	if n < 128 {
		out := make([]byte, 2+n)
		out[0] = tag
		out[1] = byte(n)
		copy(out[2:], body)
		return out
	}
	if n < 256 {
		out := make([]byte, 3+n)
		out[0] = tag
		out[1] = 0x81
		out[2] = byte(n)
		copy(out[3:], body)
		return out
	}
	out := make([]byte, 4+n)
	out[0] = tag
	out[1] = 0x82
	binary.BigEndian.PutUint16(out[2:4], uint16(n))
	copy(out[4:], body)
	return out
}

func readTLV(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	l := int(b[1])
	off := 2
	if l&0x80 != 0 {
		nbytes := l & 0x7f
		if nbytes == 0 || len(b) < 2+nbytes {
			return 0, nil, nil, false
		}
		l = 0
		for i := 0; i < nbytes; i++ {
			l = (l << 8) | int(b[2+i])
		}
		off = 2 + nbytes
	}
	if len(b) < off+l {
		return 0, nil, nil, false
	}
	return tag, b[off : off+l], b[off+l:], true
}

func readTLVExpect(b []byte, want byte) (content, rest []byte, ok bool) {
	tag, content, rest, ok := readTLV(b)
	if !ok || tag != want {
		return nil, b, false
	}
	return content, rest, true
}

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var neg bool
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// EnrichLANIdentity runs SSDP then SNMP soft probes (hostname policy: fill empty only).
func EnrichLANIdentity(ctx context.Context, hosts []Host) {
	ProbeSSDP(ctx, hosts, 2500*time.Millisecond)
	ProbeSNMP(ctx, hosts, 500*time.Millisecond, 32)
}
