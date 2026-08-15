# Windows

Install, run, and develop Network Sweeper on Windows (amd64). Also: [Linux](linux.md) · [macOS](macos.md). Capabilities and limitations: [PLATFORM.md](PLATFORM.md).

## Requirements

For a **prebuilt release binary** you do **not** need Go, Node, Docker, nmap, or other scan toolchains.

| Need | Required? | Notes |
|---|---|---|
| `network-sweeper-windows-amd64.exe` | Yes | From [GitHub Releases](https://github.com/BVisagie/network-sweeper/releases) |
| Web browser | Yes | Chrome, Edge, Firefox, etc. Opened automatically on start |
| `ping` | Recommended | Used as a discovery boost (often without Admin). Comes with Windows |
| `arp` | Optional | Used to read the OS ARP cache for MAC addresses |
| Administrator | Optional | Quieter devices; Deep checkbox is optional on Windows. Active ARP sweep is **not** available. Normal TCP scans work without elevation |

There is no `curl \| bash` installer on Windows. Download the `.exe` from Releases.

## Install and run

1. Download `network-sweeper-windows-amd64.exe` from [Releases](https://github.com/BVisagie/network-sweeper/releases).
2. Verify checksums (below).
3. If SmartScreen warns (unsigned v1 builds): **More info → Run anyway** only if you trust the source and checksum. See [PLATFORM.md](PLATFORM.md#allow-anyway-unsigned-builds).
4. Double-click the `.exe`, or in PowerShell/CMD:

```bat
network-sweeper-windows-amd64.exe
```

5. Your default browser should open to `http://127.0.0.1:<random-port>/`.

To print the URL without opening a browser:

```bat
network-sweeper-windows-amd64.exe -no-browser
```

Flags: `-no-browser`, `-version`.

## Verify checksums

Release assets include `SHA256SUMS`. Example for one file in PowerShell:

```powershell
Get-FileHash .\network-sweeper-windows-amd64.exe -Algorithm SHA256
```

Compare the hash to the matching line in `SHA256SUMS`.

## Elevation and Deep discovery

On Windows, system `ping` is already tried as a best-effort discovery boost **even without Admin and even when Deep is unchecked**. For quieter devices, optionally right-click the `.exe` → **Run as administrator**. The Deep checkbox is optional. Active ARP sweep is deferred (not implemented) on Windows in this version.

TCP discovery and findings scans work without elevation. Full matrix: [PLATFORM.md](PLATFORM.md).

## Troubleshooting

| Problem | What to try |
|---|---|
| Browser didn’t open | Run with `-no-browser` and open the printed `http://127.0.0.1:…` URL |
| SmartScreen | Verify checksums; **More info → Run anyway** only if you trust the build |
| Zero hosts | Guest Wi‑Fi or AP isolation; try Run as administrator; confirm subnet |
| Deep discovery seems ignored | Ping may already run without Admin; active ARP is deferred — check the Elevated badge and Limitations tab |
| Missing names / “Unknown” | Names fill from reverse DNS, NetBIOS, mDNS, then SSDP/SNMP hints — many IoT devices still advertise little |
| No MAC yet | ARP cache not populated yet, or Wi‑Fi client isolation / VPN path hides L2 |
| Update check fails | Enable opt-in in Settings; needs public GitHub Releases; offline networks cannot check |

## Developers

Go **1.26.5+** (see `go.mod`). Confirm with `go version`. Open a **new** terminal after install so `PATH` picks up `go`.

- Winget: `winget install GoLang.Go`
- Or the MSI from [go.dev/dl](https://go.dev/dl/)
- Optional: `winget install Git.Git` and a `make` (e.g. from Chocolatey / MSYS2) — or skip `make` and use `go test` / `go build` directly

Then:

```bat
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
go test ./...
go run ./cmd/networksweeper -no-browser
```

With `make` (if installed):

```bat
make test
make run
make build
bin\network-sweeper.exe
```

Shared contributor setup: [CONTRIBUTING.md](../CONTRIBUTING.md).
