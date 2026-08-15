# Releasing

## Prerequisites

- Public GitHub repository `BVisagie/network-sweeper` (update checks and README download links assume this).
- Push access and ability to create tags.
- CI: `.github/workflows/ci.yml` (matrix) and `.github/workflows/release.yml` (on `v*` tags).

## Cut a release

1. Ensure `main` (or the release branch) is green: `make test` locally and CI on the PR.
2. Tag a semver release (leading `v` required for the workflow):

```bash
git tag v0.2.0
git push origin v0.2.0
```

3. GitHub Actions runs `make cross`, uploads binaries + `SHA256SUMS` to the GitHub Release.
4. Smoke-test one asset per OS you care about; verify checksums.

## Artifacts

From `make cross` / release workflow:

- `network-sweeper-linux-amd64`
- `network-sweeper-linux-arm64`
- `network-sweeper-windows-amd64.exe`
- `network-sweeper-darwin-amd64`
- `network-sweeper-darwin-arm64`
- `SHA256SUMS`

Version is injected via ldflags into `internal/version.Version` (tag without leading `v`).

The Linux one-liner (`scripts/install.sh`) downloads:

- `https://github.com/BVisagie/network-sweeper/releases/latest/download/network-sweeper-linux-<arch>`
- `…/SHA256SUMS`

Keep those asset names stable. Until a non-draft release exists, the launcher fails with a plain-language message (not raw API JSON). Smoke-test `bash scripts/install.sh --help` and, after publishing, `--ephemeral --no-browser`.

## Update-check happy path

`POST /api/update` (opt-in) calls `https://api.github.com/repos/BVisagie/network-sweeper/releases/latest`.

- Needs a **public** repo and at least one **published** (non-draft) release.
- Until then the UI shows a plain-language “no releases yet” / unreachable message — not a raw status code dump.
- Keep `internal/version.Repo` in sync if the GitHub path changes.

## Signing

Code signing / notarization is deferred. Document “allow anyway” steps in README and `docs/PLATFORM.md`. Checksums are the trust bridge for v1 testers.
