package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

const appDirName = "network-sweeper"

// DefaultDir is the per-user data directory:
//
//	Linux and other Unix: $XDG_DATA_HOME/network-sweeper, else ~/.local/share/network-sweeper
//	macOS:                ~/Library/Application Support/network-sweeper
//	Windows:              %LocalAppData%\network-sweeper
func DefaultDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LocalAppData"); d != "" {
			return filepath.Join(d, appDirName), nil
		}
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, appDirName), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", appDirName), nil
	default:
		if d := os.Getenv("XDG_DATA_HOME"); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, appDirName), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if home == "" {
			return "", errors.New("no home directory")
		}
		return filepath.Join(home, ".local", "share", appDirName), nil
	}
}
