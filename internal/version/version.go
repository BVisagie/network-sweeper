package version

// Version is set at link time via -ldflags "-X github.com/BVisagie/network-sweeper/internal/version.Version=..."
var Version = "0.1.0-dev"

// Repo is the GitHub repository used for opt-in update checks.
const Repo = "BVisagie/network-sweeper"
