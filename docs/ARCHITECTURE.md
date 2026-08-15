# Architecture

Network Sweeper is a stdlib-only Go program: one binary embeds a localhost web UI and runs LAN discovery + heuristic risk labeling.

## Package map

```
cmd/networksweeper     CLI entry: flags, start API, open browser, signal shutdown
scripts/install.sh     Linux curl|bash launcher + launch menu (not a scan UI)
internal/api           Localhost HTTP, token/Origin hardening, scan orchestration, export
internal/discover      TCP discovery, optional ICMP/ARP, ARP cache MAC, reverse DNS,
                       NetBIOS/mDNS hostname fill, SSDP + SNMP soft probes
internal/scan          Findings-port TCP connect scan + service labels
internal/enrich        Short HTTP title/Server, TLS cert summary, SSH/FTP/SMTP banners
internal/risk          Heuristic findings from open ports / enrichment / host metadata
internal/netinfo       Interfaces, CIDR helpers, allowlist, default gateway (best-effort)
internal/oui           Offline MAC vendor prefix map
internal/platform      Elevation detection + capability snapshot for Limitations UI
internal/update        Opt-in GitHub Releases check
internal/version       Link-time version + public repo path for updates
web/                   Embedded UI (index.html, style.css, app.js) via embed.FS
```

## Scan flow

1. `POST /api/scan` validates targets against local subnets (or custom opt-in).
2. `discover.Engine.Discover` probes discovery ports; ICMP via system `ping` when Windows boost applies or Deep+elevated on Unix; active ARP who-has when Deep+elevated on Linux/macOS.
3. MAC from ARP cache (and ARP replies) + OUI; hosts tagged as self / gateway (or soft router guess) when known.
4. `scan.ScanHosts` probes findings ports on live hosts.
5. `enrich.Results` adds lightweight HTTP/TLS/banner hints on relevant open ports.
6. `discover.EnrichHostnames` fills empty names via NetBIOS then mDNS.
7. `discover.EnrichLANIdentity` runs SSDP (known hosts) then SNMP `public` soft probe.
8. `risk.Evaluate` builds findings; snapshot stored for UI/export (`POST /api/scan/cancel` aborts an in-flight run).

## Linux launcher

`scripts/install.sh` is a bootstrap, not a second product UI. It downloads a GitHub Release binary, verifies `SHA256SUMS`, then either runs once from a temp dir (default), launches that verified binary with `sudo` (`--sudo` or the interactive Deep-discovery choice), or copies `network-sweeper` to a prefix. Interactive prompts read `/dev/tty` so `curl | bash` still works. The dashboard remains the embedded localhost web UI. End-user steps: [linux.md](linux.md).

## Local API security

- Listen on `127.0.0.1:0` (ephemeral port only).
- Per-launch token injected into HTML; required on `/api/*` (`X-NetworkSweeper-Token` or `?token=` for downloads).
- Origin must match the local base URL (empty Origin allowed for same-origin).

## Web embedding

`web/embed.go` embeds static assets. `api.uiHandler` replaces `__SESSION_TOKEN__` and `__APP_VERSION__` in `index.html`. Do not break those placeholders.

Overview host rows use shared float tips (`data-tip`) for beginner-friendly help on Found via, open ports, names, MAC, and badges.

## Deep discovery honesty

**Deep discovery** means **ICMP via system `ping`**, and on **elevated Linux/macOS** also an **active ARP sweep**. On Windows, ICMP is attempted as a best-effort boost even without elevation (and even when Deep is unchecked); active ARP remains deferred. ARP **cache** enrichment still runs after contact on all OSes.
