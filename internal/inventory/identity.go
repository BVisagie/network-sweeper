package inventory

import (
	"fmt"
	"strings"
	"time"

	"github.com/BVisagie/network-sweeper/internal/risk"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// profileFor finds or creates the profile a scan ran from: gateway MAC plus
// the gateway's subnet. Without a gateway MAC it falls back to the subnet (or
// the scanned ranges) and marks the profile unverified. Caller holds s.mu.
func (s *Store) profileFor(snap *Snapshot) *Profile {
	mac := strings.ToLower(snap.GatewayMAC)
	subnet := snap.GatewaySubnet
	if subnet == "" {
		subnet = strings.Join(snap.Coverage.Ranges, ",")
	}
	for _, p := range s.inv.Profiles {
		if p.GatewayMAC == mac && p.Subnet == subnet {
			return p
		}
	}
	p := &Profile{
		ID:         newID("p-"),
		GatewayMAC: mac,
		Subnet:     subnet,
		Verified:   mac != "",
		Created:    snap.FinishedAt,
	}
	p.Name = defaultProfileName(p)
	if snap.GatewayIP != "" && mac != "" {
		p.Name = fmt.Sprintf("%s (gateway %s)", subnet, snap.GatewayIP)
	}
	s.inv.Profiles = append(s.inv.Profiles, p)
	return p
}

func defaultProfileName(p *Profile) string {
	if !p.Verified {
		return p.Subnet + " (gateway unknown)"
	}
	return p.Subnet
}

// assign links each host to a device in profile p, creating devices as needed.
//
// A host matches on its MAC within the profile. Hosts without a MAC, and hosts
// whose MAC answered for several addresses in this scan (a Wi-Fi extender or
// proxy ARP), are tracked by address instead, so one MAC never merges
// different machines. Hostname, vendor, or IP alone never link a host to a
// MAC-identified device, so a reused DHCP address does not inherit another
// device's names and notes. Caller holds s.mu.
func (s *Store) assign(p *Profile, snap *Snapshot) {
	macIPs := map[string]int{}
	for _, h := range snap.Hosts {
		if h.MAC != "" {
			macIPs[strings.ToLower(h.MAC)]++
		}
	}
	portsByIP := map[string]scan.Result{}
	for _, r := range snap.Ports {
		portsByIP[r.IP] = r
	}
	findingsByIP := map[string][]risk.Finding{}
	for _, f := range snap.Findings {
		findingsByIP[f.HostIP] = append(findingsByIP[f.HostIP], f)
	}
	byKey := map[string]*Device{}
	for _, d := range s.inv.Devices {
		if d.ProfileID != p.ID {
			continue
		}
		if d.Basis == BasisMAC {
			byKey["mac|"+d.MAC] = d
		} else {
			byKey["addr|"+d.Address] = d
		}
	}

	at := snap.FinishedAt
	for i := range snap.Hosts {
		h := &snap.Hosts[i]
		mac := strings.ToLower(h.MAC)
		var notes []string
		basis, key := BasisMAC, "mac|"+mac
		switch {
		case mac == "":
			basis, key = BasisAddress, "addr|"+h.IP
			notes = append(notes, "No MAC address was visible, so this device is tracked by its IP address. If another device takes the address, it will appear here.")
		case macIPs[mac] > 1:
			basis, key = BasisAddress, "addr|"+h.IP
			notes = append(notes, fmt.Sprintf("MAC %s answered for %d addresses in this scan (a Wi-Fi extender or proxy ARP does this), so this device is tracked by its IP address.", mac, macIPs[mac]))
		}
		if basis == BasisMAC && h.PrivateMAC {
			notes = append(notes, "Private (randomised) MAC: if the device picks a new one, it will show up as a new device.")
		}
		if len(h.DuplicateMACs) > 1 {
			notes = append(notes, fmt.Sprintf("%d devices answered for %s; the first reply's MAC was used.", len(h.DuplicateMACs), h.IP))
		}

		d := byKey[key]
		if d == nil {
			d = &Device{ID: newID("d-"), ProfileID: p.ID, Basis: basis, FirstSeen: at}
			if basis == BasisMAC {
				d.MAC = mac
			} else {
				d.Address = h.IP
			}
			s.inv.Devices = append(s.inv.Devices, d)
			byKey[key] = d
		}
		h.DeviceID = d.ID

		r := portsByIP[h.IP]
		obs := &Observation{
			ScanID: snap.ID, At: at, Partial: snap.Partial, Host: *h,
			Ports: r.Ports, Closed: r.Closed, Findings: findingsByIP[h.IP],
		}
		// No two hosts in one scan share a device: MAC keys are used only for a
		// MAC seen on a single address, and address keys are per IP.
		d.Last = obs
		d.LastSeen = at
		d.LastScanID = snap.ID
		d.Uncertain = notes
		d.Addresses = noteAddress(d.Addresses, h.IP, at)
		var open []int
		for _, op := range r.Ports {
			open = append(open, op.Port)
		}
		d.History = append(d.History, HistoryEntry{
			ScanID: snap.ID, At: at, IP: h.IP, Ports: open,
			Findings: len(obs.Findings), Partial: snap.Partial,
		})
	}
}

func noteAddress(list []AddressSeen, ip string, at time.Time) []AddressSeen {
	for i := range list {
		if list[i].IP == ip {
			list[i].Last = at
			return list
		}
	}
	return append(list, AddressSeen{IP: ip, First: at, Last: at})
}
