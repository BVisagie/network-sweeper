# macOS

Install, run, and develop Network Sweeper on macOS (Apple Silicon arm64 and Intel amd64). Also: [Linux](linux.md) · [Windows](windows.md). Capabilities and limitations: [PLATFORM.md](PLATFORM.md).

## Requirements

For a **prebuilt release binary** you do **not** need Go, Node, Docker, nmap, or other scan toolchains.

| Need | Required? | Notes |
|---|---|---|
| `network-sweeper-darwin-arm64` or `darwin-amd64` | Yes | From [GitHub Releases](https://github.com/BVisagie/network-sweeper/releases) |
| Web browser | Yes | Safari, Chrome, Firefox, etc. Opened automatically on start |
| `ping` | Recommended | Used for Deep discovery (ICMP) when elevated. Comes with macOS |
| `arp` | Optional | Used to read the OS ARP cache for MAC addresses |
| root (`sudo`) | Optional | Needed for **Deep discovery** (ICMP ping + active ARP). Normal TCP scans work without elevation |

There is no `curl \| bash` installer on macOS. Download the matching darwin binary from Releases.

## Install and run

1. Download `network-sweeper-darwin-arm64` (Apple Silicon) or `network-sweeper-darwin-amd64` (Intel) from [Releases](https://github.com/BVisagie/network-sweeper/releases).
2. Verify checksums (below).
3. Remove quarantine if Gatekeeper blocks, then run:

```bash
xattr -d com.apple.quarantine network-sweeper-darwin-arm64
chmod +x network-sweeper-darwin-arm64
./network-sweeper-darwin-arm64
```

Or allow via **System Settings → Privacy & Security → Open Anyway** (when you trust the source and checksum). See [PLATFORM.md](PLATFORM.md#allow-anyway-unsigned-builds).

4. The browser opens to `http://127.0.0.1:<random-port>/`. If it does not, use `-no-browser` and open the printed URL.

Flags: `-no-browser`, `-version`.

## Verify checksums

Release assets include `SHA256SUMS`.

```bash
shasum -a 256 -c SHA256SUMS
```

## Elevation and Deep discovery

Deep discovery on macOS is **ICMP via system `ping` plus an active ARP sweep**. It needs **both** `sudo` **and** the Deep checkbox on Overview (not inside Advanced options).

```bash
sudo ./network-sweeper-darwin-arm64
# Intel:
sudo ./network-sweeper-darwin-amd64
```

TCP discovery and findings scans work without elevation. Full matrix: [PLATFORM.md](PLATFORM.md).

## Troubleshooting

| Problem | What to try |
|---|---|
| Browser didn’t open | Run with `-no-browser` and open the printed `http://127.0.0.1:…` URL |
| Gatekeeper | Verify checksums; **Open Anyway**, or `xattr -d com.apple.quarantine` after you trust the build |
| Zero hosts | Guest Wi‑Fi or AP isolation; try Deep discovery with `sudo` and the Deep checkbox; confirm subnet |
| Deep discovery seems ignored | Needs `sudo` **and** the Deep checkbox (then ICMP + ARP). Check the Elevated badge and Limitations tab |
| Missing names / “Unknown” | Names fill from reverse DNS, NetBIOS, mDNS, then SSDP/SNMP hints — many IoT devices still advertise little |
| No MAC yet | ARP cache not populated yet, or Wi‑Fi client isolation / VPN path hides L2 |
| Update check fails | Enable opt-in in Settings; needs public GitHub Releases; offline networks cannot check |

## Developers

Go **1.26.5+** (see `go.mod`). Confirm with `go version`.

```bash
# Homebrew
brew install go make git
go version
```

Or install the macOS package from [go.dev/dl](https://go.dev/dl/). Open a **new** terminal after install so `PATH` picks up `go`.

Then:

```bash
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
make test
make run    # or: go run ./cmd/networksweeper -no-browser
```

Deep discovery while developing: `sudo env "PATH=$PATH" go run ./cmd/networksweeper -no-browser`, then enable the Deep checkbox.

Shared contributor setup: [CONTRIBUTING.md](../CONTRIBUTING.md).
