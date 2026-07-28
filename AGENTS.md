# Agent instructions — Network Sweeper

Guidance for Cursor, Copilot, Claude Code, and similar agents working in this repository.

## Product

Local LAN inventory + heuristic exposure findings with an embedded localhost web UI. Only scan networks the user owns or is authorized to assess.

## Hard security invariants

- Bind the UI/API to `127.0.0.1` only. Never suggest binding to `0.0.0.0` or non-loopback interfaces.
- Keep per-launch session token (`X-NetworkSweeper-Token`) and Origin checks on `/api/*`.
- Default scan targets = detected local CIDRs. Custom CIDRs outside that allowlist require explicit opt-in.
- Do not add exploit payloads, weaponized scanners, or remote-target features without strong authorization UX.
- Findings stay educational (title, description, remediation) — not attack recipes.

## Discovery semantics

- Discovery ports ≠ findings ports (coverage vs risk labeling).
- **Deep discovery** = **ICMP** via system `ping`, plus **active ARP** on elevated Linux/macOS. On Windows: ping may run as a boost without elevation (and without Deep); active ARP is deferred.
- ARP **cache** enrichment runs on all OSes after contact. Active ARP sweep is Unix Deep+elevated only.
- Never mark unimplemented capabilities as `full` when the process is elevated (Windows ARP stays `deferred`).
- Silent/firewalled hosts that miss discovery ports (and ICMP/ARP when those paths are off/unavailable) may be invisible entirely.

## Stack

- Go **stdlib only** (see `go.mod` version). Do not add module dependencies without an explicit maintainer decision.
- Vanilla `web/` (HTML/CSS/JS) embedded via `web/embed.go`. No Node toolchain.
- Cross-platform: use `internal/platform` / OS branching; do not assume Linux `/proc` on Darwin/Windows.

## Commands

- `make test` — unit tests
- `make build` / `make run` — local binary
- `make cross` — release artifacts + `SHA256SUMS`
- Version injected via ldflags into `internal/version.Version`

## Update check

- Assume public GitHub repo `BVisagie/network-sweeper` + Releases as the happy path.
- Degrade gracefully on 404 / offline with plain-language messages.
- Never dump raw API JSON in the Settings UI.

## Documentation sync

When capabilities change, update together:

- `docs/PLATFORM.md`
- `docs/ARCHITECTURE.md` (scan flow / package map)
- `README.md` (features / troubleshooting / elevation)
- Limitations UI copy / `internal/platform.Snapshot`
- Elevation how-tos (Windows Run as administrator; macOS/Linux `sudo`)
- `CONTRIBUTING.md` discovery-honesty bullet if semantics change

## Scope and license

- Prefer minimal, focused diffs; match existing style.
- Keep dashboard panel chrome visually consistent across tabs.
- Project license: **GNU GPL v3** (`LICENSE`).
