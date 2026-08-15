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
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Display())
		return
	}

	elevated := platform.IsElevated()
	srv := api.New(web.FS, elevated)
	hs, ln, err := srv.ListenAndServe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen failed: %v\n", err)
		os.Exit(1)
	}
	defer hs.Close()
	defer ln.Close()

	printStartup(srv.BaseURL, elevated)

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
