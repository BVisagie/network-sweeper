# Future plan: Tier 3+ scan enrichment

Backlog saved after shipping Tier 1 (risk rules + OUI expansion) and Tier 2 (HTTP/TLS/banner enrichment). Do not treat items below as committed roadmap; they are prioritized ideas that stay within product invariants (stdlib-only preference, educational findings, localhost UI, no exploits).

## Context (already shipped)

- Broader port→finding coverage (DBs, MSRPC/RPCbind, NetBIOS, printer, HTTP alts, Docker TLS, gateway-context)
- Expanded offline OUI map
- Post-connect enrichment: HTTP title/`Server`, TLS CN/issuer/expiry/self-signed, SSH/FTP/SMTP banners
- Findings for expired / self-signed TLS

## Tier 3 — hostname gap (docs still mark reverse DNS as partial)

### NetBIOS name query (UDP/137)

- **Effort:** medium (stdlib UDP packet)
- **Value:** high on Windows-heavy LANs
- **Notes:** Fill empty Hostname for PCs/NAS when 139/445 are open or after discovery; no elevation required; update Hostname capability copy when real

### mDNS / DNS-SD (UDP/5353)

- **Effort:** medium (multicast quirks cross-OS)
- **Value:** high on home/Apple/IoT LANs
- **Notes:** Device names for printers, Chromecast, HomePods, many IoT; more platform testing than NetBIOS

## Tier 4 — elevated / deferred discovery (coverage)

### Active ARP sweep (elevated; currently deferred)

- **Effort:** medium–high (raw sockets / OS-specific; Windows Npcap-class issues)
- **Value:** very high for quiet hosts that miss TCP discovery ports and may miss ICMP
- **Notes:** Keep `platform.Snapshot` honest (`deferred` → `elevated`/`full` only when implemented). Highest elevation payoff beyond today’s ICMP Deep path.

### SSDP / UPnP discovery (UDP multicast 1900)

- **Effort:** medium
- **Value:** high for IoT inventory (LOCATION + friendlyName)
- **Notes:** Typically no elevation; keep findings educational (e.g. “UPnP responder on LAN”), not attack recipes

### SNMP soft probe (`public` GET sysName/sysDescr)

- **Effort:** medium
- **Value:** high on printers/switches/AP gear
- **Notes:** One community-string try only (no brute force); educational finding if `public` answers; elevated optional depending on OS/raw socket needs

## Explicitly lower priority / avoid for “easy”

| Idea | Why not top-tier |
|------|------------------|
| SYN / raw half-open | Marked unavailable; portability + privilege complexity |
| Full OS fingerprinting | Out of current product framing; heavy to do well |
| SMB signing/dialect deep probe | Closer to security-tooling complexity; higher misuse optics |
| Binding UI off localhost / remote targets | Hard security invariants |

## Suggested build order when revisiting

1. NetBIOS and/or mDNS hostname enrichment
2. SSDP/UPnP inventory hints
3. Active ARP when ready to spend elevated/OS-specific effort
4. SNMP soft `public` probe (careful UX)

## Doc sync checklist (when implementing)

- [ ] `docs/PLATFORM.md` capability matrix
- [ ] `README.md` features / troubleshooting
- [ ] Limitations UI / `internal/platform.Snapshot`
- [ ] Elevation how-tos if new elevated paths appear
- [ ] `docs/ARCHITECTURE.md` scan flow
