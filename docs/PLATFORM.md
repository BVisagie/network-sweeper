# Platform capabilities and limitations

Network Sweeper runs as a **local executable** with an embedded web UI on Windows, Linux, and macOS.

Legend: **Available** = works with current privileges · **Needs elevation** = feature requires Admin/root (not the same as “app is elevated”) · **Partial** = works with limits · **Unavailable** = not implemented or blocked · **Not built yet** = deferred

## Capability matrix

### Full on all supported OSes

- IPv4 interface + CIDR detection
- TCP connect discovery (dedicated discovery port set)
- TCP findings port scan + service labels
- ARP **cache** MAC enrichment after contact + offline vendor lookup (curated names, then the full embedded IEEE MA-L registry)
- ARP **cache** discovery: on-link hosts that answered the OS's ARP lookup during TCP discovery are listed as `arp-cache` even when every discovery port is closed (no elevation needed)
- Private (randomised, locally administered) MAC badge when no vendor matches
- Hostname resolution: reverse DNS, then NetBIOS (UDP/137), then mDNS reverse PTR; SSDP/SNMP may fill remaining empty names
- Service enrichment on open findings ports: HTTP title/`Server`, TLS cert summary (CN/issuer/expiry/self-signed), SSH/FTP/SMTP banners
- SSDP/UPnP inventory hints (known hosts only) + SNMP soft `public` probe (educational findings)
- Saved history: scans, device names/notes/tags, and finding reviews in a per-user data folder (see below), with comparisons between scans of the same network
- Target preview: ranges are deduplicated and sized before a scan; selections over 1,024 addresses are refused rather than cut short
- Hardened local API (ephemeral port, per-launch token, Origin checks)
- Server-side default restriction to detected local subnets

### Elevated / partial

- **ICMP ping discovery (Deep discovery)** — On **Windows**, system `ping` is attempted as an extra discovery signal even without elevation (and even when Deep is unchecked). On **Linux/macOS**, ICMP runs only when Deep is enabled **and** the process is elevated (`sudo`). Unprivileged mode always tries TCP discovery ports first.
- **Active ARP sweep** — On **Linux/macOS**, Deep + elevation also sends ARP who-has on local interfaces to find quiet hosts, and flags **Duplicate IP** when more than one MAC answers for an address. On **Windows**, active ARP remains deferred (no Npcap-class dependency); Deep uses ICMP only.
- **Hostname resolution** — partial everywhere; reverse DNS + NetBIOS + mDNS (+ SSDP/SNMP fill). Many IoT devices still advertise little.
- **Device identification** — partial; port labels + OUI + hostname hints + HTTP/TLS/banner + SSDP/SNMP (not OS fingerprinting).

### Unavailable or deferred

- **Active ARP sweep on Windows** — deferred (not implemented).
- **SYN / raw half-open scan** — unavailable (portability).
- **Hosts behind Wi‑Fi AP / client isolation** — unavailable; peers hidden at L2.
- **Other VLANs / guest Wi‑Fi** — unavailable; only attached segments are visible.
- **Bind UI beyond localhost** — unavailable.
- **Code signing / Apple notarization** — deferred post-v1.

## Discovery incompleteness (important)

A host that does not accept connections on any **discovery** port can still appear via the OS **ARP cache** (`arp-cache`): every TCP dial makes the OS resolve the target's MAC first, so on-link hosts that answer ARP are listed without elevation. Hosts off the local segment (routed custom CIDRs), behind client isolation, or that ignore ARP too will **not appear at all** unless ICMP finds them. A device that just left the network can linger in the ARP cache for a minute or so. Static/permanent ARP entries are never listed this way, since the OS uses them without asking the network.

Discovery ports (coverage-oriented) are separate from findings ports (risk/service labeling).

## Elevation and Deep discovery

How-tos: [windows.md](windows.md) · [macos.md](macos.md) · [linux.md](linux.md).

- **Windows:** system `ping` is already tried as a best-effort discovery boost **even without Admin and even when Deep is unchecked**. For quieter devices, optionally right-click the `.exe` → **Run as administrator**. Active ARP is not available on Windows in this version.
- **macOS:** `sudo ./network-sweeper-darwin-arm64` (or `darwin-amd64`), **then** enable Deep discovery beside **Scan** (ICMP + ARP).
- **Linux:** `sudo ./network-sweeper-linux-amd64` (or `linux-arm64`), **then** enable Deep discovery (ICMP + ARP).

On Linux/macOS, Deep discovery needs both elevation and the checkbox, which sits beside **Scan** on the Devices tab. Elevated Linux/macOS runs do not save history unless `--data-dir` is given (see below).

## Saved history and data location

| OS | Default folder |
|---|---|
| Linux / other Unix | `$XDG_DATA_HOME/network-sweeper`, else `~/.local/share/network-sweeper` |
| macOS | `~/Library/Application Support/network-sweeper` |
| Windows | `%LocalAppData%\network-sweeper` |

`--data-dir DIR` overrides the folder; `--ephemeral` keeps everything in memory for the session. Elevated runs on Linux/macOS default to memory only so root never creates files in the user's inventory (pass `--data-dir` to save anyway); on Windows an elevated process keeps the same folder. Files are private (0600/0700) where the OS supports it, and an OS file lock (flock on Linux/macOS, an unshared handle on Windows) keeps a second instance from writing to the same folder; the OS releases it if the app crashes. A scan that cannot be written stays available in memory for the session, and older scans are only removed after a new one is saved. A damaged index, or one written by a newer version, is left untouched and the session runs in memory with the reason shown in the UI.

Devices are tracked per network, where a network is the gateway's MAC plus its subnet, so two networks that both use `192.168.1.0/24` stay apart. Devices match on MAC; devices without a usable MAC are tracked by IP and marked as uncertain. Comparisons report absence as "not observed" and a closed service only when its port refused the connection.

## Local API security

Binding to `127.0.0.1` alone does not stop a malicious web page from calling the local API. Network Sweeper:

1. Uses a **per-launch ephemeral port**
2. Generates a **cryptographic session token** injected into the served HTML
3. Requires `X-NetworkSweeper-Token` on `/api/*`
4. Validates `Origin` against the local base URL (or allows empty Origin for same-origin)

## Scan consent enforcement

Consent is enforced server-side:

- Default allowlist = CIDRs of detected local interfaces
- Custom CIDR outside that allowlist requires the Settings toggle **Allow custom CIDR…** (enforced server-side on `POST /api/scan`)
- API rejects disallowed ranges even if the UI is bypassed

## Running on each OS

End-user install, checksums, and elevation how-tos:

- [linux.md](linux.md)
- [windows.md](windows.md)
- [macos.md](macos.md)

Short version: run the matching release binary; a browser is required; Go is not. Optional Administrator/`sudo` for Deep discovery on macOS/Linux (ICMP + ARP); Windows often tries `ping` without elevation. Unsigned-build allow steps below.

## UI notes

The Devices table has hover tips on open ports, and the device detail explains how each device was found (`tcp/N`, `icmp`, `arp`, `arp-cache`). Prefer keeping that copy educational and short when changing discovery semantics.

## Code signing (v1 decision)

**Deferred for v1.** SmartScreen and Gatekeeper warnings are an adoption issue for unsigned security tools. Document “allow anyway” steps for testers; structure releases with checksums so signing/notarization can be added later without redesigning artifacts.

### Allow anyway (unsigned builds)

- **Windows:** SmartScreen → More info → Run anyway (when you trust the build source and checksum).
- **macOS:** System Settings → Privacy & Security → Open Anyway, or remove quarantine: `xattr -d com.apple.quarantine network-sweeper` after verifying checksums.
- **Linux:** `chmod +x` the binary; follow your distro’s policy for untrusted executables.

## CI coverage notes

GitHub Actions runs unprivileged unit/smoke tests on `windows-latest`, `ubuntu-latest`, and `macos-latest`. Privileged paths are covered with unit tests and limited Linux `sudo` checks where practical.
