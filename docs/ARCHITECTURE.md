# Architecture

Network Sweeper is a stdlib-only Go program: one binary embeds a localhost web UI and runs LAN discovery + heuristic risk labeling.

## Package map

```
cmd/networksweeper     CLI entry: flags, start API, open browser, signal shutdown
scripts/install.sh     Linux curl|bash launcher + launch menu (not a scan UI)
internal/api           Localhost HTTP, token/Origin hardening, scan planning and lifecycle,
                       inventory endpoints, JSON/CSV export (CSV cells from device text are
                       neutralised against formulas)
internal/discover      TCP discovery, optional ICMP/ARP, ARP cache MAC, reverse DNS,
                       NetBIOS/mDNS hostname fill, SSDP + SNMP soft probes
internal/scan          Findings-port TCP connect scan + service labels
internal/enrich        Short HTTP title/Server, TLS cert summary, SSH/FTP/SMTP banners
internal/risk          Findings with category, confidence, and evidence from ports / probes / host metadata
internal/inventory     Saved history: snapshots, network profiles, device identity, annotations,
                       finding reviews, comparisons (stdlib JSON, atomic writes, PID lockfile)
internal/netinfo       Interfaces, CIDR helpers, allowlist, default gateway (best-effort)
internal/oui           Offline MAC vendor lookup: curated map, then embedded IEEE MA-L registry
                       (ieee.csv, refreshed by `make oui` / internal/oui/gen)
internal/platform      Elevation detection + capability snapshot for Settings → Platform capabilities
internal/update        Opt-in GitHub Releases check
internal/version       Link-time version + public repo path for updates
web/                   Embedded UI (index.html, style.css, app.js) via embed.FS
```

## Scan flow

1. `POST /api/scan` builds the same plan as `POST /api/scan/preview`: ranges deduplicated, IPv6 rejected, at most 1,024 distinct addresses (larger selections are refused, not truncated). It then checks the plan against local subnets (or custom opt-in) and claims the single scan slot under one lock. The run gets an ID; `/api/scan/status` reports its state (starting, running, completed, canceled, timed_out, failed), phase with counters, and hosts found so far.
2. `discover.Engine.Discover` probes discovery ports; ICMP via system `ping` when Windows boost applies or Deep+elevated on Unix; active ARP who-has when Deep+elevated on Linux/macOS.
3. On-link hosts in the OS ARP cache (resolved during the TCP dials) that no probe found are added as `arp-cache` (static/permanent rows excluded); MAC from ARP cache (and ARP replies) + OUI; reverse DNS runs concurrently; hosts tagged as self / gateway (or soft router guess), private MAC (U/L bit, no vendor) and duplicate IP (several ARP replies) when known.
4. `scan.ScanHosts` probes findings ports on live hosts, recording open ports and ports that refused the connection.
5. `enrich.Results` adds lightweight HTTP/TLS/banner hints on relevant open ports and records whether a protocol answered (`OpenPort.Protocol`, `Probe`). HTTP redirects and SSDP description fetches stay on the probed device's own IP.
6. `discover.EnrichHostnames` fills empty names via NetBIOS then mDNS.
7. `discover.EnrichLANIdentity` runs SSDP (known hosts) then SNMP `public` soft probe.
8. `risk.Evaluate` builds findings: an open port alone is inferred and at most medium; a protocol answer makes a finding confirmed. `POST /api/scan/cancel` stops a run; what it saw is kept and flagged partial.
9. `inventory.Store.Record` picks the network profile (gateway MAC + subnet), links hosts to devices, saves the snapshot and index, and applies retention. The UI reads devices, history, and comparisons from `/api/inventory`, `/api/devices/{id}`, `/api/history`, and `/api/changes`.

## Linux launcher

`scripts/install.sh` is a bootstrap, not a second product UI. It downloads a GitHub Release binary, verifies `SHA256SUMS`, then either runs once from a temp dir (default), launches that verified binary with `sudo` (`--sudo` or the interactive Deep-discovery choice), or copies `network-sweeper` to a prefix. Interactive prompts read `/dev/tty` so `curl | bash` still works. The dashboard remains the embedded localhost web UI. End-user steps: [linux.md](linux.md).

## Local API security

- Listen on `127.0.0.1:0` (ephemeral port only).
- Per-launch token injected into HTML; required on `/api/*` (`X-NetworkSweeper-Token` or `?token=` for downloads).
- Origin must match the local base URL (empty Origin allowed for same-origin).

## Web embedding

`web/embed.go` embeds static assets. `api.uiHandler` replaces `__SESSION_TOKEN__` and `__APP_VERSION__` in `index.html`. Do not break those placeholders.

The Devices table and device detail use shared float tips (`data-tip`) for beginner-friendly help on open ports. Device-supplied text is HTML-escaped with bidi control characters removed.

## Deep discovery honesty

**Deep discovery** means **ICMP via system `ping`**, and on **elevated Linux/macOS** also an **active ARP sweep**. On Windows, ICMP is attempted as a best-effort boost even without elevation (and even when Deep is unchecked); active ARP remains deferred. ARP **cache** enrichment and `arp-cache` host discovery still run after contact on all OSes, unprivileged.
