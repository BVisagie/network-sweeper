package discover

import "encoding/binary"

// bpfHdrMin is the part of a Darwin struct bpf_hdr the walker reads:
// bh_tstamp (timeval32, 8) + bh_caplen (4) + bh_datalen (4) + bh_hdrlen (2).
const bpfHdrMin = 18

// eachBPFRecord calls fn with the captured frame of every record in one BPF
// read. A read can hold several records, each padded to BPF_ALIGNMENT (4 on
// Darwin). It stops at the first truncated or malformed header.
func eachBPFRecord(buf []byte, fn func(frame []byte)) {
	for off := 0; off+bpfHdrMin <= len(buf); {
		caplen := int(binary.NativeEndian.Uint32(buf[off+8:]))
		hdrlen := int(binary.NativeEndian.Uint16(buf[off+16:]))
		end := off + hdrlen + caplen
		if hdrlen < bpfHdrMin || end > len(buf) {
			return
		}
		fn(buf[off+hdrlen : end])
		off += (hdrlen + caplen + 3) &^ 3
	}
}
