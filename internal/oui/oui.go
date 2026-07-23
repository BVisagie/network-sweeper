package oui

import "strings"

// Compact built-in OUI prefix map (normalized uppercase, no separators).
// Not exhaustive — enough for common vendors in a home/lab LAN.
var prefixes = map[string]string{
	"000C29": "VMware",
	"00155D": "Microsoft Hyper-V",
	"001C42": "Parallels",
	"0050F2": "Microsoft",
	"080027": "PCS Systemtechnik / VirtualBox",
	"0A0027": "PCS Systemtechnik / VirtualBox",
	"525400": "QEMU/KVM",
	"B827EB": "Raspberry Pi Foundation",
	"DCA632": "Raspberry Pi Foundation",
	"E45F01": "Raspberry Pi Foundation",
	"F4F5E8": "Google",
	"3C5A37": "Samsung",
	"FC1855": "Apple",
	"ACBC32": "Apple",
	"A4C138": "Apple",
	"F0D1A9": "Apple",
	"001A11": "Google",
	"18B430": "Nest Labs",
	"44D9E7": "Ubiquiti",
	"802AA8": "Ubiquiti",
	"FCECDA": "Ubiquiti",
	"B4FBE4": "Ubiquiti",
	"0418D6": "Ubiquiti",
	"E063DA": "Ubiquiti",
	"002722": "Ubiquiti",
	"001E58": "D-Link",
	"1C7EE5": "D-Link",
	"C0A0BB": "D-Link",
	"00E04C": "Realtek",
	"F8E43B": "ASUSTek",
	"001132": "Synology",
	"000C43": "Ralink",
	"247189": "Espressif",
	"30AEA4": "Espressif",
	"84F3EB": "Espressif",
	"A020A6": "Espressif",
	"BCFF4D": "Espressif",
	"CC50E3": "Espressif",
	"24586E": "zte",
	"001E10": "Huawei",
	"00E0FC": "Huawei",
	"048C16": "Huawei",
	"8CE117": "Huawei",
	"0019E0": "Sony",
	"000413": "Snom",
	"001565": "Xiaomi",
	"28E31F": "Xiaomi",
	"64B473": "Xiaomi",
	"7811DC": "Xiaomi",
	"F0B429": "Xiaomi",
	"2C4D54": "ASUSTek",
	"04D4C4": "ASUSTek",
	"001B63": "Apple",
	"3C22FB": "Apple",
	"DC56E7": "Apple",
	"000D3A": "Microsoft",
	"7C1E52": "Microsoft",
	"281878": "Microsoft",
	"C83A35": "Tenda",
	"C8D719": "Cisco",
	"00000C": "Cisco",
	"00170F": "Cisco",
	"F4CFE2": "Cisco",
	"B0A737": "TP-Link",
	"50C7BF": "TP-Link",
	"60E327": "TP-Link",
	"98DAC4": "TP-Link",
	"A0F3C1": "TP-Link",
	"14CC20": "TP-Link",
	"EC086B": "TP-Link",
	"C0C9E3": "TP-Link",
	"30B5C2": "TP-Link",
	"909A4A": "TP-Link",
}

// Lookup returns a vendor name for a MAC address, or empty string.
func Lookup(mac string) string {
	n := normalize(mac)
	if len(n) < 6 {
		return ""
	}
	if v, ok := prefixes[n[:6]]; ok {
		return v
	}
	return ""
}

func normalize(mac string) string {
	mac = strings.ToUpper(mac)
	var b strings.Builder
	for _, r := range mac {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
