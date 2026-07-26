package oui

import "strings"

// Compact built-in OUI prefix map (normalized uppercase, no separators).
// Not exhaustive — enough for common vendors in a home/lab LAN.
var prefixes = map[string]string{
	// Hypervisors / virtual NICs
	"000C29": "VMware",
	"00155D": "Microsoft Hyper-V",
	"001C42": "Parallels",
	"00163E": "Xensource",
	"0050F2": "Microsoft",
	"080027": "PCS Systemtechnik / VirtualBox",
	"0A0027": "PCS Systemtechnik / VirtualBox",
	"525400": "QEMU/KVM",

	// Raspberry Pi / SBC / MCU
	"B827EB": "Raspberry Pi Foundation",
	"DCA632": "Raspberry Pi Foundation",
	"E45F01": "Raspberry Pi Foundation",
	"247189": "Espressif",
	"30AEA4": "Espressif",
	"84F3EB": "Espressif",
	"A020A6": "Espressif",
	"BCFF4D": "Espressif",
	"CC50E3": "Espressif",
	"681AB2": "Espressif",
	"A4CF12": "Espressif",
	"24B2DE": "Espressif",
	"10521C": "Espressif",
	"7C9EBD": "Espressif",
	"DC4F22": "Espressif",
	"98F4AB": "Espressif",

	// Apple
	"FC1855": "Apple",
	"ACBC32": "Apple",
	"A4C138": "Apple",
	"F0D1A9": "Apple",
	"001B63": "Apple",
	"3C22FB": "Apple",
	"DC56E7": "Apple",
	"8419F8": "Apple",
	"AC87A3": "Apple",
	"F0B479": "Apple",
	"A88E24": "Apple",
	"D0E140": "Apple",
	"3C0754": "Apple",
	"14109F": "Apple",
	"F4F15A": "Apple",
	"BC926B": "Apple",
	"A4B197": "Apple",

	// Google / Nest / Chromecast-class
	"F4F5E8": "Google",
	"001A11": "Google",
	"18B430": "Nest Labs",
	"D8EB46": "Google",
	"F4F5D8": "Google",
	"54E019": "Google",
	"3C5AB4": "Google",
	"94EB2C": "Google",

	// Ubiquiti
	"44D9E7": "Ubiquiti",
	"802AA8": "Ubiquiti",
	"FCECDA": "Ubiquiti",
	"B4FBE4": "Ubiquiti",
	"0418D6": "Ubiquiti",
	"E063DA": "Ubiquiti",
	"002722": "Ubiquiti",
	"70F395": "Ubiquiti",
	"74ACB9": "Ubiquiti",
	"F09FC2": "Ubiquiti",
	"18E829": "Ubiquiti",
	"24A43C": "Ubiquiti",

	// TP-Link
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

	// Netgear
	"001E2A": "Netgear",
	"A04246": "Netgear",
	"20E52A": "Netgear",
	"C40415": "Netgear",
	"9C3DCF": "Netgear",
	"6CB0CE": "Netgear",
	"E046EE": "Netgear",
	"08BD43": "Netgear",
	"A00460": "Netgear",
	"F87394": "Netgear",

	// Amazon
	"44650D": "Amazon",
	"FC65DE": "Amazon",
	"84D6D0": "Amazon",
	"68FAA4": "Amazon",
	"40B4CD": "Amazon",
	"74C246": "Amazon",
	"00FC8B": "Amazon",
	"B47C9C": "Amazon",
	"F0D2F1": "Amazon",

	// Sonos / Philips Hue
	"000E58": "Sonos",
	"5CAAFD": "Sonos",
	"B8E937": "Sonos",
	"949F3E": "Sonos",
	"48A6B8": "Sonos",
	"7828CA": "Sonos",
	"542A1B": "Sonos",
	"001788": "Philips Lighting",
	"ECB5FA": "Philips Lighting",

	// ASUS / D-Link / Tenda / Synology
	"F8E43B": "ASUSTek",
	"2C4D54": "ASUSTek",
	"04D4C4": "ASUSTek",
	"00E018": "ASUSTek",
	"2C56DC": "ASUSTek",
	"04D9F5": "ASUSTek",
	"107B44": "ASUSTek",
	"382C4A": "ASUSTek",
	"001E58": "D-Link",
	"1C7EE5": "D-Link",
	"C0A0BB": "D-Link",
	"C83A35": "Tenda",
	"001132": "Synology",

	// Cisco / Linksys
	"C8D719": "Cisco",
	"00000C": "Cisco",
	"00170F": "Cisco",
	"F4CFE2": "Cisco",
	"0026CA": "Cisco",
	"004096": "Cisco",
	"F87B20": "Cisco",
	"001E13": "Cisco-Linksys",
	"00259C": "Cisco-Linksys",
	"C0C1C0": "Cisco-Linksys",
	"20AA4B": "Cisco-Linksys",
	"0018F8": "Cisco-Linksys",

	// Huawei / Xiaomi / Samsung / Sony / zte
	"001E10": "Huawei",
	"00E0FC": "Huawei",
	"048C16": "Huawei",
	"8CE117": "Huawei",
	"001565": "Xiaomi",
	"28E31F": "Xiaomi",
	"64B473": "Xiaomi",
	"7811DC": "Xiaomi",
	"F0B429": "Xiaomi",
	"B0E434": "Xiaomi",
	"7C49EB": "Xiaomi",
	"50EC50": "Xiaomi",
	"64CC2E": "Xiaomi",
	"8CDEF9": "Xiaomi",
	"AC233F": "Xiaomi",
	"34CE00": "Xiaomi",
	"3C5A37": "Samsung",
	"001E33": "Samsung",
	"5C0A5B": "Samsung",
	"8CC8CD": "Samsung",
	"D0C1B1": "Samsung",
	"F0E77E": "Samsung",
	"0019E0": "Sony",
	"24586E": "zte",

	// Intel / Realtek / Broadcom / AzureWave
	"001B21": "Intel",
	"A0A8CD": "Intel",
	"F48E38": "Intel",
	"8C8D28": "Intel",
	"001E67": "Intel",
	"B4055D": "Intel",
	"00A0C9": "Intel",
	"E8B1FC": "Intel",
	"00E04C": "Realtek",
	"000C43": "Ralink",
	"001018": "Broadcom",
	"001BE9": "Broadcom",
	"28C2DD": "AzureWave",

	// Dell / HP / Microsoft
	"F0DEF1": "Dell",
	"001590": "Dell",
	"D4BEB8": "Dell",
	"0018A0": "Dell",
	"F8B156": "Dell",
	"18A99B": "Dell",
	"001E0B": "HP",
	"3C4A92": "HP",
	"9440C9": "HP",
	"B499BA": "HP",
	"708BCD": "HP",
	"C4346B": "HP",
	"001A4B": "HP",
	"002264": "HP",
	"9C8E99": "HP",
	"0017A4": "HP",
	"0001E6": "HP",
	"002481": "HP",
	"0025B3": "HP",
	"000D3A": "Microsoft",
	"7C1E52": "Microsoft",
	"281878": "Microsoft",
	"001DD8": "Microsoft",

	// Misc home/lab
	"000413": "Snom",
	"00A0DE": "Yamaha",
	"001DD9": "Hon Hai / Foxconn",
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
