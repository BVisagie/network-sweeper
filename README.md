# Network Sweeper

Cross-platform local LAN scanner with an embedded web UI. Discovers hosts on your local network, lists open common services, and surfaces heuristic cybersecurity exposure findings.

Supported OS: **Windows**, **Linux**, **macOS** (amd64 and arm64 where builds are published).

License: [GNU GPL v3](LICENSE).

## Client requirements (end users)

For a **prebuilt release binary**, you do **not** need Go, Node, Docker, nmap, or other scan toolchains.

| Need | Required? | Notes |
|---|---|---|
| Network Sweeper binary for your OS/arch | Yes | From [GitHub Releases](https://github.com/BVisagie/network-sweeper/releases) (or build from source) |
| Web browser | Yes | Chrome, Edge, Firefox, Safari, etc. Opened automatically on start |
| `ping` | Recommended | Used for optional ICMP discovery (esp. Windows boost / Deep discovery). Comes with Windows, macOS, and typical Linux installs |
| `arp` | Optional | Used to read the OS ARP cache for MAC addresses. Present on Windows/macOS; on Linux the app prefers `/proc/net/arp` and does not require the `arp` binary |
| Administrator / root | Optional | Needed for reliable **Deep discovery** (ICMP) on macOS/Linux. On Windows, system `ping` is often tried even without Admin. Normal TCP scans work without elevation |
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
5. Optional: enable **Deep discovery** next to Scan my network. On Windows, ping is often tried even without Admin; Run as administrator still helps for quieter devices.

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
4. Optional Deep discovery:

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
3. Optional Deep discovery:

```bash
sudo ./network-sweeper-darwin-arm64
```

## First-run UI flow

1. Confirm you are authorized to scan; review the listed local subnets.
2. Click **Scan my network**. Optionally enable **Deep discovery** (ICMP ping) beside the button; use **Advanced options** for a custom CIDR.
3. Review hosts on Overview (summary strip, filter, copy IP/MAC) and **Security risks**.
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
| Deep discovery seems ignored | On macOS/Linux it needs `sudo` plus the Deep checkbox. On Windows, ping may already run without Admin; check the Elevated badge and Limitations tab |
| Update check fails | Enable opt-in in Settings; needs public GitHub Releases; offline networks cannot check |

## Build from source (developers)

Requirements:

- Go **1.26.5** or newer (see `go.mod`)
- `make` (optional; you can call `go` directly)
- Same optional OS tools as above (`ping`, browser)

```bash
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
go run ./cmd/networksweeper
```

Or:

```bash
make build
./bin/network-sweeper
```

Tests and cross-compile:

```bash
make test
make cross   # writes dist/ binaries + SHA256SUMS
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/RELEASING.md](docs/RELEASING.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## Features

- Local interface / subnet detection + best-effort default gateway
- Unprivileged TCP **discovery** ports + broader **findings** ports
- Best-effort ICMP via system `ping` (**Deep discovery** on Linux/macOS when elevated; Windows often boosts with ping even without Admin)
- ARP **cache** MAC enrichment + compact OUI vendor lookup (no active ARP sweep)
- Heuristic security findings with remediation text
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

## License

[GNU General Public License v3.0](LICENSE).
