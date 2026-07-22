package version

import "strings"

// Version is set at link time via -ldflags "-X github.com/BVisagie/network-sweeper/internal/version.Version=..."
// Prefer semver without a leading "v" (e.g. "0.1.0"). DisplayVersion adds one when needed.
var Version = "0.1.0-dev"

// Repo is the GitHub repository used for opt-in update checks.
const Repo = "BVisagie/network-sweeper"

// Canonical returns Version without a leading "v".
func Canonical() string {
	return strings.TrimPrefix(strings.TrimSpace(Version), "v")
}

// Display returns a user-facing version with a single leading "v".
func Display() string {
	c := Canonical()
	if c == "" {
		return ""
	}
	return "v" + c
}
