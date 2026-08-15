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
- Findings are **heuristic and educational**, not proof of exploitability.
- Soft probes (e.g. SNMP community `public`, SSDP) are single-shot inventory checks — not brute force or exploit modules.
- Do not send exploit payloads or weaponized scan modules as contributions.
