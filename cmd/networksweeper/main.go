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

func main() {
	noBrowser := flag.Bool("no-browser", false, "do not open the default browser")
	flag.Parse()

	elevated := platform.IsElevated()
	srv := api.New(web.FS, elevated)
	hs, ln, err := srv.ListenAndServe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen failed: %v\n", err)
		os.Exit(1)
	}
	defer hs.Close()
	defer ln.Close()

	fmt.Printf("Network Sweeper %s\n", version.Display())
	fmt.Printf("Dashboard: %s\n", srv.BaseURL)
	fmt.Printf("OS: %s/%s  elevated: %v\n", runtime.GOOS, runtime.GOARCH, elevated)
	fmt.Println("Listening on loopback only. Press Ctrl+C to stop.")

	if !*noBrowser {
		openBrowser(srv.BaseURL)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println("\nShutting down…")
	_ = hs.Close()
	time.Sleep(100 * time.Millisecond)
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
