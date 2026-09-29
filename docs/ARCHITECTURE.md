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
internal/assistant     AI chat backends: Claude/Codex CLI with every tool off, run as the invoking
                       user (never root), or a loopback OpenAI-compatible model server
internal/analysis      Model-agnostic AI analysis prompt (embedded prompt.md) from the latest scan, with
                       MAC and name masking; the app only shows it, never sends it
internal/inventory     Saved history: snapshots, network profiles, device identity, annotations,
                       finding reviews, comparisons (stdlib JSON, atomic writes, OS file lock)
internal/netinfo       Interfaces, CIDR helpers, allowlist, default gateway (best-effort)
internal/oui           Offline MAC vendor lookup: curated map, then embedded IEEE MA-L registry
                       (ieee.csv, refreshed by `make oui` / internal/oui/gen)
internal/platform      Elevation detection + capability snapshot for Settings → Platform capabilities
internal/update        Opt-in GitHub Releases check
internal/version       Link-time version + public repo path for updates
web/                   Embedded UI (index.html, style.css, app.js) via embed.FS
testdata/ui            Synthetic data directory for checking the UI without scanning (written by
                       TestWriteUIData in internal/inventory; see CONTRIBUTING.md)
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
9. `inventory.Store.Record` picks the network profile (gateway MAC + subnet), links hosts to devices, saves the snapshot and index, and applies retention. The UI reads devices, history, and comparisons from `/api/inventory`, `/api/devices/{id}`, `/api/history`, and `/api/changes`. `POST /api/history/delete` is refused (409) while a scan runs, since the scan would save itself into the history being deleted; the UI also locks the scan's settings and the delete buttons until the scan ends.
10. **Analyze with AI** calls `GET /api/analysis-prompt`. `analysis.Build` fills the prompt with the profile's latest scan: devices seen, ports and probe evidence, findings with review state, tags, coverage (including whether the scan ran elevated, recorded at scan time), and changes since the previous scan. MACs (`maskMacs`) and names, tags, and notes (`maskNames`) are masked unless the request sets them to `0`. Masking also scrubs those values from banners, titles, and finding text. Device text stays inside a JSON block that the prompt tells the model to treat as untrusted data, and backticks are escaped so it cannot close the block. The prompt carries when it was generated, and asks the model to open with the scan's age when the scan is over a day old. The **Analyze** tab (shown once a scan exists; the **Analyze with AI** button beside Scan opens it) notes a scan older than a day or partial, with a Scan again button, and shows the text under a risk notice, and copying, downloading or sending it waits for the user to acknowledge that risk. Nothing is sent from the app itself.
11. **Ask an AI on this computer** (the Analyze tab's conversation, behind the same acknowledgement; it survives tab switches until the page reloads). The prompt endpoint also returns a key from each `device-N` and `mac-N` to the real device and MAC. It stays in the page and is never part of the prompt. Once a conversation starts, the left column lists "Devices in this analysis" (mentioned first), and references in the conversation become chips such as `device-14 · Hue bridge` that open the device's details: `GET /api/assistant` reports which backends are installed; `POST /api/assistant/ask` sends one turn, meaning the reviewed prompt plus the conversation so far. Each turn runs from scratch: the CLIs get the whole transcript on stdin in an empty temp dir, and the local server gets it as chat messages. Claude runs with `--tools ""`; Codex runs `exec` in its read-only sandbox with its shell, code, browser, apps and plugin features disabled, and is refused if its version lacks any of those switches. Under sudo, the child drops to the invoking user (credential, `HOME`, `PATH`) in its own process group, which Stop kills. One request runs at a time. The local model server must be on loopback, which is checked both on the URL and at connect time.

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
