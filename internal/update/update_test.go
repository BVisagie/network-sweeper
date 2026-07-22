package update

import "testing"

func TestNewer(t *testing.T) {
	if !newer("0.2.0", "0.1.0") {
		t.Fatal("expected 0.2.0 > 0.1.0")
	}
	if newer("0.1.0", "0.1.0") {
		t.Fatal("same version should not be newer")
	}
	if newer("0.1.0", "0.2.0-dev") {
		t.Fatal("0.1.0 should not be newer than 0.2.0")
	}
}
