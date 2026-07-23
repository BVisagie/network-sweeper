# Architecture

Network Sweeper is a stdlib-only Go program: one binary embeds a localhost web UI and runs LAN discovery + heuristic risk labeling.

## Package map

```
cmd/networksweeper     CLI entry: flags, start API, open browser, signal shutdown
internal/api           Localhost HTTP, token/Origin hardening, scan orchestration, export
internal/discover      TCP discovery ports, optional ICMP (ping), ARP cache MAC, reverse DNS
internal/scan          Findings-port TCP connect scan + service labels
internal/risk          Heuristic findings from open ports / host metadata
internal/netinfo       Interfaces, CIDR helpers, allowlist, default gateway (best-effort)
internal/oui           Offline MAC vendor prefix map
internal/platform      Elevation detection + capability snapshot for Limitations UI
internal/update        Opt-in GitHub Releases check
internal/version       Link-time version + public repo path for updates
web/                   Embedded UI (index.html, style.css, app.js) via embed.FS
```

## Scan flow

1. `POST /api/scan` validates targets against local subnets (or custom opt-in).
2. `discover.Engine.Discover` probes discovery ports; ICMP via system `ping` when Windows boost applies or Deep+elevated on Unix.
3. MAC from ARP cache + OUI; hosts tagged as self / gateway (or soft router guess) when known.
4. `scan.ScanHosts` probes findings ports on live hosts.
5. `risk.Evaluate` builds findings; snapshot stored for UI/export (`POST /api/scan/cancel` aborts an in-flight run).

## Local API security

- Listen on `127.0.0.1:0` (ephemeral port only).
- Per-launch token injected into HTML; required on `/api/*` (`X-NetworkSweeper-Token` or `?token=` for downloads).
- Origin must match the local base URL (empty Origin allowed for same-origin).

## Web embedding

`web/embed.go` embeds static assets. `api.uiHandler` replaces `__SESSION_TOKEN__` and `__APP_VERSION__` in `index.html`. Do not break those placeholders.

## Deep discovery honesty

**Deep discovery** means **ICMP via system `ping`**. On Linux/macOS it requires the Deep checkbox **and** an elevated process. On Windows, ICMP is attempted as a best-effort boost even without elevation (and even when Deep is unchecked). It does **not** run an active ARP sweep. ARP enrichment is cache-only.
