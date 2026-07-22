# Network Sweeper

Cross-platform local LAN scanner with an embedded web UI. Discovers hosts on your local network, lists open common services, and surfaces heuristic cybersecurity exposure findings.

## Quick start

```bash
go run ./cmd/networksweeper
```

Or build a binary:

```bash
make build
./bin/network-sweeper
```

The app binds **only** to `127.0.0.1` on an ephemeral port, opens your browser, and injects a per-launch session token into the UI.

Flags:

- `-no-browser` — print the URL and do not open a browser

## Features (v1)

- Local interface / subnet detection
- Unprivileged TCP **discovery** ports (coverage-oriented) + broader **findings** ports
- Best-effort ICMP via system `ping` (often needs elevation on Linux/macOS; Windows may work without)
- ARP cache MAC enrichment + compact OUI vendor lookup
- Heuristic security findings with remediation text
- Server-enforced scan targets: default = detected local subnets; custom CIDR requires explicit opt-in
- Hardened local API: Origin checks + per-launch token
- Opt-in “check for updates” (GitHub Releases; default off)
- Limitations panel documenting OS gaps (see [docs/PLATFORM.md](docs/PLATFORM.md))

## Security notes

- Only scan networks you own or are authorized to assess.
- Loopback bind alone is **not** enough against malicious browser pages; the API requires a session token and validates `Origin`.
- Unsigned binaries may trigger SmartScreen (Windows) or Gatekeeper (macOS). Code signing is deferred for v1 — see PLATFORM.md.

## Development

```bash
make test
make build
```

Cross-compile:

```bash
make cross
```

## License

See repository license if present; otherwise all rights reserved by the author until specified.
