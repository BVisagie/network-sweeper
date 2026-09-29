# Network Sweeper

Local LAN inventory in one Go binary: discover devices on networks attached to your machine, keep names and notes for them, see what changed since the last scan, and review exposure findings that say what evidence backs them. Not a remote pentest suite or exploit framework.

After a scan, the **Analyze** tab builds a prompt that works with any AI model. It holds the scan's data, with MAC addresses and names masked by default, and asks the model for hardening advice. You can copy it, or have the conversation right in the tab with an AI on this computer: the Claude or Codex CLI (run with every tool off, and never as root) or a local model server such as llama.cpp or Ollama. Network Sweeper makes no AI calls itself. Sharing your network's details with an AI service is at your own risk.

**Only scan networks you own or are authorized to assess.** The UI binds to `127.0.0.1` only.

[Linux](docs/linux.md) · [Windows](docs/windows.md) · [macOS](docs/macos.md) · [Releases](https://github.com/BVisagie/network-sweeper/releases)

## Install

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/BVisagie/network-sweeper/main/scripts/install.sh | bash
```

Do not pipe that through `sudo` (`sudo curl | bash` only elevates curl; `curl | sudo bash` runs the installer as root). Menu option 2 / `--sudo` elevates the verified binary. Checksums and Deep discovery: [docs/linux.md](docs/linux.md).

Windows and macOS: download the matching asset from [Releases](https://github.com/BVisagie/network-sweeper/releases) and follow [docs/windows.md](docs/windows.md) or [docs/macos.md](docs/macos.md). No Go, Node, or nmap required to run a prebuilt binary.

A browser opens the dashboard (`-no-browser` prints the URL; `-version` prints the version). History is saved per user; `-ephemeral` keeps nothing, `-data-dir DIR` picks the folder ([details](docs/PLATFORM.md#saved-history-and-data-location)).

## Docs

| | |
|---|---|
| Run | [Linux](docs/linux.md) · [Windows](docs/windows.md) · [macOS](docs/macos.md) |
| Product | [Platform capabilities](docs/PLATFORM.md) · [Architecture](docs/ARCHITECTURE.md) |
| Project | [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Releasing](docs/RELEASING.md) |

## License

[GNU GPL v3](LICENSE) — Copyright (C) 2026 Bernard Visagie ([NOTICE](NOTICE)).
