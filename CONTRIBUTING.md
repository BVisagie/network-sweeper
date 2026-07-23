# Contributing

Thanks for helping improve Network Sweeper.

## Setup

- Go version from `go.mod` (currently **1.26.5+**).
- Optional: `make` for `test` / `build` / `cross`.

```bash
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
make test
make build
./bin/network-sweeper -no-browser
```

## Guidelines

- Prefer **stdlib-only** Go. New module dependencies need a clear maintainer decision.
- UI is vanilla HTML/CSS/JS under `web/` — no Node toolchain.
- **Security invariants:** bind `127.0.0.1` only; keep session token + Origin checks; default targets = local CIDRs; custom ranges need explicit opt-in.
- Discovery honesty: Deep = ICMP; ARP = cache only; never mark unimplemented capabilities as `full` when elevated.
- When capabilities change, update `docs/PLATFORM.md`, README, and `internal/platform.Snapshot` together.
- Keep diffs focused; match existing style.
- License: GNU GPL v3 (`LICENSE`).

## Tests

```bash
make test
```

Add parser/unit tests for networking helpers (fixtures, not live LAN). Mock HTTP for update-check paths.

## Docs for agents

See [AGENTS.md](AGENTS.md) for AI assistant constraints.
