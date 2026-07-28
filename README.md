# Network Sweeper

A **local-first LAN inventory tool**: one stdlib Go binary embeds a localhost web UI, discovers devices on networks attached to your machine, lists common open services, and surfaces heuristic exposure tips (not a remote pentest suite or exploit framework).

Supported OS: **Windows**, **Linux**, **macOS** (amd64 and arm64 where builds are published).

License: [GNU GPL v3](LICENSE) — Copyright (C) 2026 Bernard Visagie ([NOTICE](NOTICE)).

## Client requirements (end users)

For a **prebuilt release binary**, you do **not** need Go, Node, Docker, nmap, or other scan toolchains.

| Need | Required? | Notes |
|---|---|---|
| Network Sweeper binary for your OS/arch | Yes | From [GitHub Releases](https://github.com/BVisagie/network-sweeper/releases) (or build from source) |
| Web browser | Yes | Chrome, Edge, Firefox, Safari, etc. Opened automatically on start |
| `ping` | Recommended | Used for optional ICMP discovery (esp. Windows boost / Deep discovery). Comes with Windows, macOS, and typical Linux installs |
| `arp` | Optional | Used to read the OS ARP cache for MAC addresses. Present on Windows/macOS; on Linux the app prefers `/proc/net/arp` and does not require the `arp` binary |
| Administrator / root | Optional | Needed for **Deep discovery** on macOS/Linux (ICMP ping + active ARP). On Windows, system `ping` is often tried even without Admin; active ARP is not available. Normal TCP scans work without elevation |
| Go 1.26.5+ | Only if building from source | Not needed to run release binaries |

No Python, Java, or package managers are required to run the app.

## Verify checksums

Release assets include `SHA256SUMS`.

```bash
# macOS / Linux
shasum -a 256 -c SHA256SUMS
```

```powershell
# Windows PowerShell (example for one file)
Get-FileHash .\network-sweeper-windows-amd64.exe -Algorithm SHA256
```

## Run from a release binary

Download the asset matching your OS from Releases, verify checksums when provided, then:

### Windows

1. Download `network-sweeper-windows-amd64.exe`.
2. If SmartScreen warns (unsigned v1 builds): **More info → Run anyway** only if you trust the source and checksum. See [docs/PLATFORM.md](docs/PLATFORM.md).
3. Double-click the `.exe`, or in PowerShell/CMD:

```bat
network-sweeper-windows-amd64.exe
```

4. Your default browser should open to `http://127.0.0.1:<random-port>/`.
5. On Windows, ping is often tried even without Admin and even if Deep is unchecked. Optional: **Run as administrator** for quieter devices; Deep checkbox is optional on Windows. Active ARP sweep is not available on Windows in this version.

To print the URL without opening a browser:

```bat
network-sweeper-windows-amd64.exe -no-browser
```

### Linux

1. Download `network-sweeper-linux-amd64` or `network-sweeper-linux-arm64`.
2. Make it executable and run:

```bash
chmod +x network-sweeper-linux-amd64
./network-sweeper-linux-amd64
```

3. Browser opens to the local dashboard. If `xdg-open` is missing, use `-no-browser` and open the printed URL manually.
4. Optional Deep discovery (ICMP + ARP; enable the Deep checkbox after starting with `sudo`):

```bash
sudo ./network-sweeper-linux-amd64
```

### macOS

1. Download `network-sweeper-darwin-amd64` (Intel) or `network-sweeper-darwin-arm64` (Apple Silicon).
2. Remove quarantine if Gatekeeper blocks (after verifying checksums), then run:

```bash
xattr -d com.apple.quarantine network-sweeper-darwin-arm64
chmod +x network-sweeper-darwin-arm64
./network-sweeper-darwin-arm64
```

Or allow via **System Settings → Privacy & Security → Open Anyway**.
3. Optional Deep discovery (ICMP + ARP; enable the Deep checkbox after starting with `sudo`):

```bash
sudo ./network-sweeper-darwin-arm64
```

## First-run UI flow

1. Confirm you are authorized to scan; review the listed local subnets.
2. Click **Scan my network**. Optionally enable **Deep discovery** beside the button (ICMP; on elevated Linux/macOS also ARP). Use **Advanced options** for a custom CIDR.
3. Review hosts on Overview (summary strip, filter, copy IP/MAC, hover tips on Found via / ports / names) and **Security risks**.
4. Read **Limitations** for OS-specific gaps (silent hosts, AP isolation, unsigned builds, elevation).

Flags:

- `-no-browser` — print the dashboard URL and do not open a browser

The app binds **only** to `127.0.0.1` on an ephemeral port and uses a per-launch session token in the UI.

## Troubleshooting

| Problem | What to try |
|---|---|
| Browser didn’t open | Run with `-no-browser` and open the printed `http://127.0.0.1:…` URL |
| Gatekeeper / SmartScreen | Verify checksums; use OS “Open anyway” / Run anyway steps above |
| Zero hosts | Guest Wi‑Fi or AP isolation; try Deep discovery (and `sudo` / Run as administrator on macOS/Linux); confirm subnet |
| Deep discovery seems ignored | On macOS/Linux it needs `sudo` **and** the Deep checkbox (then ICMP + ARP). On Windows, ping may already run without Admin; active ARP is deferred — check the Elevated badge and Limitations tab |
| Missing names / “Unknown” | Names fill from reverse DNS, NetBIOS, mDNS, then SSDP/SNMP hints — many IoT devices still advertise little |
| No MAC yet | ARP cache not populated yet, or Wi‑Fi client isolation / VPN path hides L2; MAC often appears after the OS talks to the host |
| Update check fails | Enable opt-in in Settings; needs public GitHub Releases; offline networks cannot check |

## Build from source (developers)

Requirements once Go is installed:

- Go **1.26.5** or newer (see `go.mod`)
- `make` (optional; you can call `go` directly)
- Same optional OS tools as end users (`ping`, browser)
- No Node toolchain — the UI is plain files under `web/`

### Install Go (dev machines)

Confirm with `go version` (need **1.26.5+**). If your distro’s package is older, use the [official Go install](https://go.dev/dl/) instead of the package manager.

**Fedora / RHEL-family**

```bash
sudo dnf install -y golang make git
go version
```

**Debian / Ubuntu**

```bash
sudo apt update
sudo apt install -y golang-go make git
go version
```

If `apt` ships an older Go, install from [go.dev/dl](https://go.dev/dl/) (tarball under `/usr/local` or `$HOME/sdk`) and put `go` on your `PATH`.

**macOS**

```bash
# Homebrew
brew install go make git
go version
```

Or install the macOS package from [go.dev/dl](https://go.dev/dl/).

**Windows**

- Winget: `winget install GoLang.Go`
- Or the MSI from [go.dev/dl](https://go.dev/dl/)
- Optional: `winget install Git.Git` and a `make` (e.g. from Chocolatey / MSYS2) — or skip `make` and use `go test` / `go build` directly

Open a **new** terminal after install so `PATH` picks up `go`.

### Run / build

```bash
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
go run ./cmd/networksweeper
```

Handy in an IDE terminal (prints the URL, no browser):

```bash
make run
# same as: go run ./cmd/networksweeper -no-browser
```

Or a binary:

```bash
make build
./bin/network-sweeper          # Windows: bin\network-sweeper.exe
```

Tests and cross-compile:

```bash
make test
make cross   # writes dist/ binaries + SHA256SUMS
```

Deep discovery while developing on Linux/macOS needs elevation **and** the Deep checkbox (ICMP + ARP), e.g. `sudo go run ./cmd/networksweeper -no-browser` (keep `go` on `sudo`’s `PATH`, or use `sudo env "PATH=$PATH" go run …`).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/RELEASING.md](docs/RELEASING.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## Features

- Local interface / subnet detection + best-effort default gateway
- Unprivileged TCP **discovery** ports + broader **findings** ports
- Best-effort ICMP via system `ping` (**Deep discovery** on Linux/macOS when elevated; Windows often boosts with ping even without Admin)
- Active ARP sweep during Deep discovery on elevated Linux/macOS (Windows deferred)
- ARP **cache** MAC enrichment + compact OUI vendor lookup
- Hostname resolution: reverse DNS, NetBIOS (UDP/137), mDNS; SSDP/SNMP may fill remaining empty names
- Lightweight service enrichment: HTTP titles/`Server`, TLS cert summary, SSH/FTP/SMTP banners
- SSDP/UPnP hints (known hosts) and SNMP `public` soft probe with educational findings
- Heuristic security findings with remediation text (including DB/RPC/admin ports, TLS, UPnP, SNMP)
- Overview host table with beginner-friendly hover tips (Found via, ports, names, badges)
- **This device** / **Gateway** / **Router?** (guess) badges, host filter, copy IP/MAC, scan summary
- Server-enforced scan targets: default = detected local subnets; custom CIDR requires Settings opt-in
- Hardened local API: Origin checks + per-launch token
- Opt-in “check for updates” (GitHub Releases; default off; contacts GitHub only when enabled)
- Limitations panel documenting OS gaps (see [docs/PLATFORM.md](docs/PLATFORM.md))

Changelog: GitHub [Releases](https://github.com/BVisagie/network-sweeper/releases).

## Security notes

- Only scan networks you own or are authorized to assess.
- Loopback bind alone is **not** enough against malicious browser pages; the API requires a session token and validates `Origin`.
- Unsigned binaries may trigger SmartScreen (Windows) or Gatekeeper (macOS). Code signing is deferred for v1 — see PLATFORM.md.
- Vulnerability reports: see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Copyright (C) 2026 Bernard Visagie. See [NOTICE](NOTICE).

[GNU General Public License v3.0](LICENSE).
