# Platform capabilities and limitations

Network Sweeper runs as a **local executable** with an embedded web UI on Windows, Linux, and macOS.

Legend: **full** = unprivileged in typical home setups · **elevated** = needs Admin/root/capabilities · **partial** = works with limits · **unavailable** = not implemented or blocked by the network/OS · **deferred** = intentionally postponed

## Capability matrix

### Full on all supported OSes

- IPv4 interface + CIDR detection
- TCP connect discovery (dedicated discovery port set)
- TCP findings port scan + service labels
- ARP cache MAC enrichment after contact + offline OUI vendor lookup
- Hardened local API (ephemeral port, per-launch token, Origin checks)
- Server-side default restriction to detected local subnets

### Elevated / partial

- **Active ARP sweep** — elevated on Windows/Linux/macOS. Raw/L2 sockets need Admin / `CAP_NET_RAW` / root.
- **ICMP ping discovery** — partial on Windows (system ping / IP Helper may work without full elevation); elevated on Linux/macOS for reliable ICMP. Unprivileged mode uses TCP discovery first.
- **Hostnames (DNS / mDNS / NetBIOS)** — partial everywhere; many IoT devices advertise little.
- **OS / device fingerprint** — partial; port heuristics only in v1.

### Unavailable or deferred

- **SYN / raw half-open scan** — unavailable in v1 (portability).
- **Hosts behind Wi‑Fi AP / client isolation** — unavailable; peers hidden at L2.
- **Other VLANs / guest Wi‑Fi** — unavailable; only attached segments are visible.
- **Bind UI beyond localhost** — unavailable in v1.
- **Code signing / Apple notarization** — deferred post-v1.

## Discovery incompleteness (important)

In **unprivileged** mode, a host that does not accept connections on any **discovery** port will **not appear at all** — not merely with missing MAC/vendor. Locked-down IoT/media devices are often invisible until Deep discovery (ARP/ICMP with elevation) succeeds.

Discovery ports (coverage-oriented) are separate from findings ports (risk/service labeling).

## Local API security

Binding to `127.0.0.1` alone does not stop a malicious web page from calling the local API. Network Sweeper:

1. Uses a **per-launch ephemeral port**
2. Generates a **cryptographic session token** injected into the served HTML
3. Requires `X-NetworkSweeper-Token` on `/api/*`
4. Validates `Origin` against the local base URL (or allows empty Origin for same-origin)

## Scan consent enforcement

Consent is enforced server-side:

- Default allowlist = CIDRs of detected local interfaces
- Custom CIDR outside that allowlist requires explicit Settings opt-in (“I am authorized…”)
- API rejects disallowed ranges even if the UI is bypassed

## Running on each OS

End-user install and dependency details (including what is *not* required) live in the root [README.md](../README.md#client-requirements-end-users).

Short version:

- **Windows / Linux / macOS:** run the matching release binary; a browser is required; Go is not.
- **Optional:** Administrator/`sudo` for Deep discovery; system `ping` for ICMP; unsigned-build allow steps below.

## Code signing (v1 decision)

**Deferred for v1.** SmartScreen and Gatekeeper warnings are an adoption issue for unsigned security tools. Document “allow anyway” steps for testers; structure releases with checksums so signing/notarization can be added later without redesigning artifacts.

### Allow anyway (unsigned builds)

- **Windows:** SmartScreen → More info → Run anyway (when you trust the build source and checksum).
- **macOS:** System Settings → Privacy & Security → Open Anyway, or remove quarantine: `xattr -d com.apple.quarantine network-sweeper` after verifying checksums.
- **Linux:** `chmod +x` the binary; follow your distro’s policy for untrusted executables.

## CI coverage notes

GitHub Actions runs unprivileged unit/smoke tests on `windows-latest`, `ubuntu-latest`, and `macos-latest`. Full elevated ARP sweeps are not assumed available on all runners; privileged paths are covered with unit tests and limited Linux `sudo` checks where practical.
