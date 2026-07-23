# Platform capabilities and limitations

Network Sweeper runs as a **local executable** with an embedded web UI on Windows, Linux, and macOS.

Legend: **Available** = works with current privileges · **Needs elevation** = feature requires Admin/root (not the same as “app is elevated”) · **Partial** = works with limits · **Unavailable** = not implemented or blocked · **Not built yet** = deferred

## Capability matrix

### Full on all supported OSes

- IPv4 interface + CIDR detection
- TCP connect discovery (dedicated discovery port set)
- TCP findings port scan + service labels
- ARP **cache** MAC enrichment after contact + offline OUI vendor lookup
- Hardened local API (ephemeral port, per-launch token, Origin checks)
- Server-side default restriction to detected local subnets

### Elevated / partial

- **ICMP ping discovery (Deep discovery)** — On **Windows**, system `ping` is attempted as an extra discovery signal even without elevation (and even when Deep is unchecked). On **Linux/macOS**, ICMP runs only when Deep is enabled **and** the process is elevated (`sudo`). Unprivileged mode always tries TCP discovery ports first. Deep discovery does **not** perform an active ARP sweep.
- **Hostname (reverse DNS)** — partial everywhere; reverse DNS only (no mDNS/NetBIOS queries). Many IoT devices advertise little.
- **Device identification** — partial; port service labels + OUI vendor lookup only (not OS fingerprinting).

### Unavailable or deferred

- **Active ARP sweep** — deferred (not implemented).
- **SYN / raw half-open scan** — unavailable (portability).
- **Hosts behind Wi‑Fi AP / client isolation** — unavailable; peers hidden at L2.
- **Other VLANs / guest Wi‑Fi** — unavailable; only attached segments are visible.
- **Bind UI beyond localhost** — unavailable.
- **Code signing / Apple notarization** — deferred post-v1.

## Discovery incompleteness (important)

A host that does not accept connections on any **discovery** port will **not appear at all** unless ICMP finds it — not merely with missing MAC/vendor. Locked-down IoT/media devices are often invisible until ping succeeds (**Deep discovery** + elevation on Linux/macOS; Windows often already tries ping).

Discovery ports (coverage-oriented) are separate from findings ports (risk/service labeling).

## Elevation and Deep discovery

- **Windows:** system `ping` is already tried as a best-effort discovery boost **even without Admin and even when Deep is unchecked**. For quieter devices, optionally right-click the `.exe` → **Run as administrator**. Enabling the Deep checkbox is optional on Windows; elevation mainly improves ping reliability.
- **macOS:** `sudo ./network-sweeper-darwin-arm64` (or `darwin-amd64`), **then** enable Deep discovery beside **Scan my network**.
- **Linux:** `sudo ./network-sweeper-linux-amd64` (or `linux-arm64`), **then** enable Deep discovery.

On Linux/macOS, Deep discovery needs both elevation and the checkbox. Deep is on the Overview scan row (not inside Advanced options). Advanced options cover custom CIDR and export.

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

End-user install and dependency details (including what is *not* required) live in the root [README.md](../README.md#client-requirements-end-users).

Short version:

- **Windows / Linux / macOS:** run the matching release binary; a browser is required; Go is not.
- **Optional:** Administrator/`sudo` for Deep discovery on macOS/Linux; system `ping` for ICMP (Windows often tries ping without elevation); unsigned-build allow steps below.

## Code signing (v1 decision)

**Deferred for v1.** SmartScreen and Gatekeeper warnings are an adoption issue for unsigned security tools. Document “allow anyway” steps for testers; structure releases with checksums so signing/notarization can be added later without redesigning artifacts.

### Allow anyway (unsigned builds)

- **Windows:** SmartScreen → More info → Run anyway (when you trust the build source and checksum).
- **macOS:** System Settings → Privacy & Security → Open Anyway, or remove quarantine: `xattr -d com.apple.quarantine network-sweeper` after verifying checksums.
- **Linux:** `chmod +x` the binary; follow your distro’s policy for untrusted executables.

## CI coverage notes

GitHub Actions runs unprivileged unit/smoke tests on `windows-latest`, `ubuntu-latest`, and `macos-latest`. Privileged paths are covered with unit tests and limited Linux `sudo` checks where practical.
