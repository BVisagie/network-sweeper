package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/BVisagie/network-sweeper/internal/api"
	"github.com/BVisagie/network-sweeper/internal/inventory"
	"github.com/BVisagie/network-sweeper/internal/platform"
	"github.com/BVisagie/network-sweeper/internal/version"
	"github.com/BVisagie/network-sweeper/web"
)

// Palette matches web/style.css and scripts/install.sh.
const (
	ansiReset  = "\033[0m"
	ansiAccent = "\033[38;2;62;207;142m"
	ansiFg     = "\033[38;2;231;242;236m"
	ansiMuted  = "\033[38;2;138;163;150m"
)

func main() {
	noBrowser := flag.Bool("no-browser", false, "do not open the default browser")
	showVersion := flag.Bool("version", false, "print version and exit")
	dataDir := flag.String("data-dir", "", "keep scan history and device notes in this directory")
	ephemeral := flag.Bool("ephemeral", false, "keep nothing after exit: history lives in memory for this session")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Display())
		return
	}
	if *ephemeral && *dataDir != "" {
		fmt.Fprintln(os.Stderr, "--ephemeral and --data-dir cannot be combined")
		os.Exit(2)
	}

	elevated := platform.IsElevated()
	store := openStore(*dataDir, *ephemeral, elevated)
	defer store.Close()
	srv := api.New(web.FS, elevated)
	srv.Store = store
	hs, ln, err := srv.ListenAndServe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen failed: %v\n", err)
		store.Close()
		os.Exit(1)
	}
	defer hs.Close()
	defer ln.Close()

	printStartup(srv.BaseURL, elevated)
	printStorage(store.Status())

	if !*noBrowser {
		openBrowser(srv.BaseURL)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println()
	fmt.Println(paint(ansiMuted, "Shutting down…"))
	_ = hs.Close()
	time.Sleep(100 * time.Millisecond)
}

func printStartup(baseURL string, elevated bool) {
	fmt.Printf("%s %s\n", paint(ansiAccent, "Network Sweeper"), paint(ansiFg, version.Display()))
	fmt.Printf("%s %s\n", paint(ansiMuted, "Dashboard:"), paint(ansiAccent, baseURL))
	fmt.Printf("%s %s/%s  elevated: %v\n", paint(ansiMuted, "OS:"), runtime.GOOS, runtime.GOARCH, elevated)
	fmt.Println(paint(ansiMuted, "Listening on loopback only. Press Ctrl+C to stop."))
}

// openStore picks where history lives. Elevated runs on Linux/macOS stay in
// memory unless --data-dir is given, so root never creates files in the
// user's inventory; on Windows an elevated process keeps the same profile.
func openStore(dataDir string, ephemeral, elevated bool) *inventory.Store {
	if ephemeral {
		return inventory.Memory(inventory.ModeEphemeral, "Started with --ephemeral: nothing is saved after exit.")
	}
	if dataDir == "" && elevated && runtime.GOOS != "windows" {
		return inventory.Memory(inventory.ModeEphemeral, "Running elevated: history is not saved, so root never writes into your inventory. Pass --data-dir to save anyway.")
	}
	if dataDir == "" {
		d, err := inventory.DefaultDir()
		if err != nil {
			return inventory.Memory(inventory.ModeUnavailable, fmt.Sprintf("No data directory (%v). Pass --data-dir to save history.", err))
		}
		dataDir = d
	}
	return inventory.Open(dataDir)
}

func printStorage(st inventory.Status) {
	switch st.Mode {
	case inventory.ModePersistent:
		fmt.Printf("%s %s\n", paint(ansiMuted, "History:"), paint(ansiFg, st.Dir))
	default:
		fmt.Printf("%s %s\n", paint(ansiMuted, "History:"), paint(ansiFg, "not saved. "+st.Reason))
	}
}

func shouldColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func paint(code, s string) string {
	if !shouldColor() {
		return s
	}
	return code + s + ansiReset
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
