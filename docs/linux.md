# Linux

Install, run, and develop Network Sweeper on Linux (amd64 and arm64). Also: [Windows](windows.md) · [macOS](macos.md). Capabilities and limitations: [PLATFORM.md](PLATFORM.md).

## Requirements

For a **prebuilt release binary** you do **not** need Go, Node, Docker, nmap, or other scan toolchains.

| Need | Required? | Notes |
|---|---|---|
| `network-sweeper-linux-amd64` or `linux-arm64` | Yes | From [GitHub Releases](https://github.com/BVisagie/network-sweeper/releases), or the one-liner below |
| Web browser | Yes | Opened automatically when a display is available |
| `curl` + `sha256sum` | For the one-liner | GNU coreutils `sha256sum` |
| `ping` | Recommended | Used for Deep discovery (ICMP) when elevated |
| `arp` | Optional | Not required; the app prefers `/proc/net/arp` |
| root (`sudo`) | Optional | Needed for **Deep discovery** (ICMP ping + active ARP). Normal TCP scans work without elevation |

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash
```

The launcher shows a short menu. **Enter** (option 1) downloads the latest GitHub Release, verifies `SHA256SUMS`, and **runs once from a temp directory** (nothing left on `PATH`). Your browser opens the same localhost dashboard as a normal run.

Option 2 runs that verified binary with `sudo` (Deep discovery). Option 3 installs `network-sweeper` to `~/.local/bin` or a path you type, then **install and launch** or **install only**.

`sudo curl … | bash` only elevates `curl`, not the app. Do **not** `curl | sudo bash` (that runs the installer as root). Elevate the verified binary instead — menu option 2, `--sudo`, or after a persistent install:

```bash
sudo network-sweeper
```

Prefer to inspect the script first:

```bash
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh -o /tmp/ns-install.sh
less /tmp/ns-install.sh
bash /tmp/ns-install.sh
```

Non-interactive examples (skips the menu):

```bash
# Run once (same as a non-TTY default)
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash -s -- --ephemeral

# Run once with sudo (Deep discovery; elevates the verified binary, not the script)
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash -s -- --sudo

# Install to ~/.local/bin and launch
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash -s -- --install

# Install only
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash -s -- --install-only --prefix "$HOME/.local/bin"
```

On SSH/headless sessions with no display, the launcher passes `-no-browser` and prints the dashboard URL. The installer downloads a **published release** (not `main` source) and will fail with a plain-language message until a Release exists. See [SECURITY.md](../SECURITY.md).

## Manual download

1. Download `network-sweeper-linux-amd64` or `network-sweeper-linux-arm64` from [Releases](https://github.com/BVisagie/network-sweeper/releases).
2. Verify checksums (below), then:

```bash
chmod +x network-sweeper-linux-amd64
./network-sweeper-linux-amd64
```

3. The browser opens to `http://127.0.0.1:<random-port>/`. If `xdg-open` is missing, use `-no-browser` and open the printed URL manually.

Flags: `-no-browser` (print the URL only), `-version`.

## Verify checksums

Release assets include `SHA256SUMS`.

```bash
sha256sum -c SHA256SUMS
# or: shasum -a 256 -c SHA256SUMS
```

The one-liner verifies the matching Linux asset before run or install. On mismatch it refuses to continue.

## Elevation and Deep discovery

Deep discovery on Linux is **ICMP via system `ping` plus an active ARP sweep**. It needs **both** `sudo` **and** the Deep checkbox on Overview (not inside Advanced options).

From the one-liner, choose **Run once with sudo** or pass `--sudo` (the launcher runs the checksum-verified binary with sudo, not the script). You can also:

```bash
sudo ./network-sweeper-linux-amd64
# after a persistent install:
sudo network-sweeper
```

TCP discovery and findings scans work without elevation. Full matrix: [PLATFORM.md](PLATFORM.md).

## Troubleshooting

| Problem | What to try |
|---|---|
| Browser didn’t open | Run with `-no-browser` and open the printed `http://127.0.0.1:…` URL (`xdg-open` may be missing) |
| One-liner fails | Needs a published GitHub Release + `SHA256SUMS`; inspect `scripts/install.sh` first; do not `curl \| sudo bash` |
| `sudo curl … \| bash` still shows not elevated | `sudo` only applies to `curl`. Choose **Run once with sudo**, pass `--sudo`, or install then `sudo network-sweeper`. If you just used `sudo curl`, the launcher offers to elevate when credentials are still cached |
| Checksum mismatch | The launcher refuses to run. Re-download, or install a verified asset from Releases by hand |
| Zero hosts | Guest Wi‑Fi or AP isolation; try Deep discovery with `sudo` and the Deep checkbox; confirm subnet |
| Deep discovery seems ignored | Needs `sudo` **and** the Deep checkbox (then ICMP + ARP). Check the Elevated badge and Limitations tab |
| Missing names / “Unknown” | Names fill from reverse DNS, NetBIOS, mDNS, then SSDP/SNMP hints — many IoT devices still advertise little |
| No MAC yet | ARP cache not populated yet, or Wi‑Fi client isolation / VPN path hides L2 |
| Update check fails | Enable opt-in in Settings; needs public GitHub Releases; offline networks cannot check |

## Developers

Go **1.26.5+** (see `go.mod`). Confirm with `go version`. If your distro’s package is older, use the [official Go install](https://go.dev/dl/).

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

Then:

```bash
git clone https://github.com/BVisagie/network-sweeper.git
cd network-sweeper
make test
make run    # or: go run ./cmd/networksweeper -no-browser
```

Deep discovery while developing: `sudo env "PATH=$PATH" go run ./cmd/networksweeper -no-browser`, then enable the Deep checkbox.

Shared contributor setup: [CONTRIBUTING.md](../CONTRIBUTING.md).
