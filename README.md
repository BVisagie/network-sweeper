# Network Sweeper

Local LAN inventory in one Go binary: discover devices on networks attached to your machine, list common open services, and read heuristic exposure tips. Not a remote pentest suite or exploit framework.

**Only scan networks you own or are authorized to assess.** The UI binds to `127.0.0.1` only.

[Linux](docs/linux.md) · [Windows](docs/windows.md) · [macOS](docs/macos.md) · [Releases](https://github.com/BVisagie/network-sweeper/releases)

## Install

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash
```

Do not pipe that through `sudo`. Menu, checksums, and Deep discovery: [docs/linux.md](docs/linux.md).

Windows and macOS: download the matching asset from [Releases](https://github.com/BVisagie/network-sweeper/releases) and follow [docs/windows.md](docs/windows.md) or [docs/macos.md](docs/macos.md). No Go, Node, or nmap required to run a prebuilt binary.

A browser opens the dashboard (`-no-browser` prints the URL; `-version` prints the version).

## Docs

| | |
|---|---|
| Run | [Linux](docs/linux.md) · [Windows](docs/windows.md) · [macOS](docs/macos.md) |
| Product | [Platform capabilities](docs/PLATFORM.md) · [Architecture](docs/ARCHITECTURE.md) |
| Project | [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Releasing](docs/RELEASING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) |

## License

[GNU GPL v3](LICENSE) — Copyright (C) 2026 Bernard Visagie ([NOTICE](NOTICE)).
