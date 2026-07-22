# Network Sweeper

Cross-platform local LAN scanner with an embedded web UI. Discovers hosts on your local network, lists open common services, and surfaces heuristic cybersecurity exposure findings.

Supported OS: **Windows**, **Linux**, **macOS** (amd64 and arm64 where builds are published).

## Client requirements (end users)

For a **prebuilt release binary**, you do **not** need Go, Node, Docker, nmap, or other scan toolchains.

| Need | Required? | Notes |
|---|---|---|
| Network Sweeper binary for your OS/arch | Yes | From [GitHub Releases](https://github.com/BVisagie/network-sweeper/releases) (or build from source) |
| Web browser | Yes | Chrome, Edge, Firefox, Safari, etc. Opened automatically on start |
| `ping` | Recommended | Used for optional ICMP discovery (esp. Windows boost / Deep discovery). Comes with Windows, macOS, and typical Linux installs |
| `arp` | Optional | Used to read the OS ARP cache for MAC addresses. Present on Windows/macOS; on Linux the app prefers `/proc/net/arp` and does not require the `arp` binary |
| Administrator / root | Optional | Only for **Deep discovery** (better chance of finding silent/firewalled hosts). Normal scans work without elevation |
| Go 1.26.5+ | Only if building from source | Not needed to run release binaries |

No Python, Java, or package managers are required to run the app.

## Run from a release binary

Download the asset matching your OS from Releases, verify checksums when provided (`SHA256SUMS`), then:

### Windows

1. Download `network-sweeper-windows-amd64.exe`.
2. If SmartScreen warns (unsigned v1 builds): **More info → Run anyway** only if you trust the source and checksum. See [docs/PLATFORM.md](docs/PLATFORM.md).
3. Double-click the `.exe`, or in PowerShell/CMD:

```bat
network-sweeper-windows-amd64.exe
```

4. Your default browser should open to `http://127.0.0.1:<random-port>/`.
5. Optional Deep discovery: right-click → **Run as administrator**, then enable Deep discovery in the UI.

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

(Or grant capabilities later; v1 typically uses root via `sudo` for elevated mode.)

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

1. Confirm you are authorized to scan the network.
2. Review local interfaces / subnets (scans default to those only).
3. Click **Start scan**.
4. See **Overview** (hosts) and **Security risks** (findings).
5. Read **Limitations** for OS-specific gaps (silent hosts, AP isolation, unsigned builds, etc.).

Flags:

- `-no-browser` — print the dashboard URL and do not open a browser

The app binds **only** to `127.0.0.1` on an ephemeral port and uses a per-launch session token in the UI.

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

## License

See repository license if present; otherwise all rights reserved by the author until specified.
