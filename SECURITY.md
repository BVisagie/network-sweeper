# Security

Network Sweeper is an **active LAN scanner**. Only use it on networks you own or are explicitly authorized to assess.

## Reporting vulnerabilities

Please report security issues privately to the repository owner via GitHub Security Advisories (preferred) or by contacting the maintainer listed on the GitHub profile for [BVisagie/network-sweeper](https://github.com/BVisagie/network-sweeper).

Include OS, version (`-version`, or the UI version pill), and steps to reproduce.

## Linux installer (`scripts/install.sh`)

The README one-liner downloads this script from GitHub and runs it. That is convenience, not a substitute for reading the script — prefer saving it and inspecting with `less` first.

The script then fetches a **published release binary** (not `main` source) and verifies it against `SHA256SUMS` before running or installing. Interactive prompts read from `/dev/tty` so they work when the script is piped. The default action is ephemeral (temp directory). The dashboard still binds to `127.0.0.1` only.

Do not `curl | sudo bash` (runs the installer as root). `sudo curl | bash` only elevates curl, not the app. After checksum verification, elevate only the binary: launcher `--sudo` / menu “Run once with sudo”, or `sudo network-sweeper` after a persistent install.

## Scope notes

- The local API binds to loopback and uses a per-launch token + Origin checks. Loopback alone is not sufficient against malicious browser pages.
- Findings are **heuristic and educational**, not proof of exploitability. Each says whether a device response confirms it or only an open port suggests it.
- Saved history (device names, notes, MACs, scan results) stays on this machine in a per-user folder with private file permissions; nothing is uploaded. `--ephemeral` keeps nothing after exit.
- **Analyze with AI** builds text for you to copy, or to hand to an AI on this computer. The app itself calls no AI service and stores no API keys. The Claude and Codex CLIs send what you share to their providers under your login. They run with every tool off (Claude `--tools ""`; Codex with its shell, code, browser and plugin features disabled, and refused if a version lacks one of those switches), in an empty temp folder, and never as root: under sudo they run as the user who started sudo. The local model server option accepts loopback addresses only. MACs, names, tags, and notes are masked by default, but IP addresses, vendors, services, and findings remain. Pasting it into an AI service is your choice and your risk. The prompt tells the model to treat device-supplied text as data, which reduces prompt injection from hostile device names or banners but cannot rule it out.
- Soft probes (e.g. SNMP community `public`, SSDP) are single-shot inventory checks — not brute force or exploit modules.
- HTTP enrichment follows at most one redirect, and SSDP device descriptions are fetched, only on the probed device's own IP address and without environment proxies.
- Do not send exploit payloads or weaponized scan modules as contributions.
