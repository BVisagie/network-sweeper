# Security

Network Sweeper is an **active LAN scanner**. Only use it on networks you own or are explicitly authorized to assess.

## Reporting vulnerabilities

Please report security issues privately to the repository owner via GitHub Security Advisories (preferred) or by contacting the maintainer listed on the GitHub profile for [BVisagie/network-sweeper](https://github.com/BVisagie/network-sweeper).

Include OS, version (`-no-browser` prints the URL; UI shows the version pill), and steps to reproduce.

## Scope notes

- The local API binds to loopback and uses a per-launch token + Origin checks. Loopback alone is not sufficient against malicious browser pages.
- Findings are **heuristic and educational**, not proof of exploitability.
- Do not send exploit payloads or weaponized scan modules as contributions.
