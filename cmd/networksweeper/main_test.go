package main

import (
	"os"
	"testing"
)

func TestShouldColorHonorsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if shouldColor() {
		t.Fatal("NO_COLOR should disable ANSI")
	}
}

func TestPaintPlainWhenNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := paint(ansiAccent, "hello")
	if got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestShouldColorFalseWhenStdoutNotCharDevice(t *testing.T) {
	// CI and `go test` almost always have a non-TTY stdout.
	if os.Getenv("NO_COLOR") != "" {
		t.Skip("NO_COLOR set in environment")
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		t.Skip("stdout is a TTY")
	}
	if shouldColor() {
		t.Fatal("expected no color when stdout is not a terminal")
	}
}
