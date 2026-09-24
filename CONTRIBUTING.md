# Contributing

Thanks for helping improve Network Sweeper.

## Setup

1. Install Go **1.27.1+** (and optional `make` / `git`) for your OS — see the **Developers** section in [docs/linux.md](docs/linux.md), [docs/windows.md](docs/windows.md), or [docs/macos.md](docs/macos.md).
2. Confirm: `go version`
3. Clone and verify:

```bash
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
make test
make run    # or: go run ./cmd/networksweeper -no-browser
```

No Node install is required. End-user release binaries do not need Go at all.

## Guidelines

- Prefer **stdlib-only** Go. New module dependencies need a clear maintainer decision.
- UI is vanilla HTML/CSS/JS under `web/` — no Node toolchain.
- **Security invariants:** bind `127.0.0.1` only; keep session token + Origin checks; default targets = local CIDRs; custom ranges need explicit opt-in.
- Discovery honesty: Deep = ICMP, plus active ARP on elevated Linux/macOS (Windows ARP stays deferred). ARP cache enrichment and `arp-cache` discovery (hosts the OS resolved during TCP dials) run on all OSes without elevation. Never mark unimplemented capabilities as `full` when elevated.
- Evidence honesty: an open port alone is an inferred finding, never a confirmed one; missing or partial observations are "not observed", and a service is only reported closed when its port refused the connection.
- When capabilities change, update together: `docs/PLATFORM.md`, `docs/ARCHITECTURE.md`, the README hub, OS runbooks (`docs/linux.md` / `windows.md` / `macos.md`), Settings → Platform capabilities (`internal/platform.Snapshot`), and elevation how-tos.
- Keep diffs focused; match existing style.
- License: GNU GPL v3 (`LICENSE`); copyright in `NOTICE`.

## Tests

```bash
make test
```

Add parser/unit tests for networking helpers (fixtures, not live LAN). Mock HTTP for update-check paths.

## Docs for agents

See [AGENTS.md](AGENTS.md) for AI assistant constraints.
