package version

import "testing"

func TestDisplayNoDoubleV(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "0.1.0"
	if Display() != "v0.1.0" {
		t.Fatalf("got %q", Display())
	}
	Version = "v0.1.0"
	if Display() != "v0.1.0" {
		t.Fatalf("got %q from tagged form", Display())
	}
	if Canonical() != "0.1.0" {
		t.Fatalf("canonical=%q", Canonical())
	}
}
