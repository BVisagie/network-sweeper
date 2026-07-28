//go:build linux

package discover

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"github.com/BVisagie/network-sweeper/internal/netinfo"
)

func arpSweepSupported() bool { return true }

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

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
			for ip, mac := range arpSweepIfaceLinux(ctx, iface, localIP, probe, timeout) {
				out[ip] = mac
			}
		}
	}
	return out
}

func arpSweepIfaceLinux(ctx context.Context, iface net.Interface, srcIP net.IP, dsts []net.IP, timeout time.Duration) map[string]string {
	out := map[string]string{}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return out
	}
	defer syscall.Close(fd)

	var sll syscall.SockaddrLinklayer
	sll.Ifindex = iface.Index
	sll.Halen = 6
	copy(sll.Addr[:], iface.HardwareAddr)
	if err := syscall.Bind(fd, &sll); err != nil {
		return out
	}

	want := map[string]bool{}
	for _, ip := range dsts {
		if ctx.Err() != nil {
			return out
		}
		frame := buildARPRequest(iface.HardwareAddr, srcIP.To4(), ip.To4())
		_, _ = syscall.Write(fd, frame)
		want[ip.String()] = true
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	buf := make([]byte, 128)
	for len(want) > 0 && time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		remaining := time.Until(deadline)
		tv := syscall.NsecToTimeval(remaining.Nanoseconds())
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, err := syscall.Read(fd, buf)
		if err != nil || n < 42 {
			continue
		}
		ip, mac, ok := parseARPReplyAny(buf[:n])
		if !ok || !want[ip] {
			continue
		}
		out[ip] = mac
		delete(want, ip)
	}
	return out
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
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

func parseARPReplyAny(frame []byte) (ip, mac string, ok bool) {
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
