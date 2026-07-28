//go:build darwin

package discover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/BVisagie/network-sweeper/internal/netinfo"
)

func arpSweepSupported() bool { return true }

// Darwin BPF ioctl constants (sys/bpf.h).
const (
	biocgblen    = 0x40044266
	biocsblen    = 0xc0044266
	biocsetif    = 0x8020426c
	biocflush    = 0x20004268
	biocimmediate = 0x80044270
	biochdrcmplt = 0x80044275
)

const ifnamsiz = 16

func sweepARP(ctx context.Context, targets []*net.IPNet, timeout time.Duration) map[string]string {
	out := map[string]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if ctx.Err() != nil {
			return out
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			localIP := ipNet.IP.To4()
			var probe []net.IP
			for _, target := range targets {
				if target == nil || target.IP.To4() == nil {
					continue
				}
				for _, ip := range netinfo.HostsInCIDR(ipNet, 1024) {
					if !target.Contains(ip) || ip.Equal(localIP) {
						continue
					}
					probe = append(probe, ip)
				}
			}
			if len(probe) == 0 {
				continue
			}
			for ip, mac := range arpSweepIfaceDarwin(ctx, iface, localIP, probe, timeout) {
				out[ip] = mac
			}
		}
	}
	return out
}

func arpSweepIfaceDarwin(ctx context.Context, iface net.Interface, srcIP net.IP, dsts []net.IP, timeout time.Duration) map[string]string {
	out := map[string]string{}
	f, err := openBPF()
	if err != nil {
		return out
	}
	defer f.Close()
	fd := int(f.Fd())

	if err := bpfSetIF(fd, iface.Name); err != nil {
		return out
	}
	_ = ioctlInt(fd, biocimmediate, 1)
	_ = ioctlInt(fd, biochdrcmplt, 1)
	_ = ioctlVoid(fd, biocflush)

	want := map[string]bool{}
	for _, ip := range dsts {
		if ctx.Err() != nil {
			return out
		}
		frame := buildARPRequestDarwin(iface.HardwareAddr, srcIP.To4(), ip.To4())
		_, _ = f.Write(frame)
		want[ip.String()] = true
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	buf := make([]byte, 4096)
	for len(want) > 0 && time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		_ = f.SetReadDeadline(deadline)
		n, err := f.Read(buf)
		if err != nil || n < 18 {
			continue
		}
		// BPF record header: bh_tstamp(8/16), bh_caplen(4), bh_datalen(4), bh_hdrlen(2) — varies by arch.
		// Parse conservatively: scan for ARP ethertype in buffer.
		for off := 0; off+42 <= n; off++ {
			if off+14 <= n && binary.BigEndian.Uint16(buf[off+12:off+14]) == 0x0806 {
				ip, mac, ok := parseARPReplyAnyDarwin(buf[off:n])
				if ok && want[ip] {
					out[ip] = mac
					delete(want, ip)
				}
				break
			}
		}
	}
	return out
}

func openBPF() (*os.File, error) {
	for i := 0; i < 256; i++ {
		f, err := os.OpenFile(fmt.Sprintf("/dev/bpf%d", i), os.O_RDWR, 0)
		if err == nil {
			return f, nil
		}
	}
	return nil, syscall.ENOENT
}

func bpfSetIF(fd int, name string) error {
	var ifr [ifnamsiz + 16]byte // ifreq with sockaddr padding
	copy(ifr[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(biocsetif), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlInt(fd int, req uintptr, v int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(&v)))
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlVoid(fd int, req uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func buildARPRequestDarwin(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	frame := make([]byte, 42)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	copy(frame[22:28], srcMAC)
	copy(frame[28:32], srcIP)
	copy(frame[38:42], dstIP)
	return frame
}

func parseARPReplyAnyDarwin(frame []byte) (ip, mac string, ok bool) {
	if len(frame) < 42 {
		return "", "", false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
		return "", "", false
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 2 {
		return "", "", false
	}
	return net.IP(frame[28:32]).String(), net.HardwareAddr(frame[22:28]).String(), true
}

var (
	_ = biocgblen
	_ = biocsblen
)
