package assistant

import "testing"

func TestValidateLocalURLStaysOnThisComputer(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080", "http://localhost:11434/", "http://[::1]:1234/v1", "http://127.1.2.3:8080"} {
		if _, err := ValidateLocalURL(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://192.168.1.5:8080", "http://example.com", "http://127.0.0.1.evil.com:8080",
		"http://user:pw@127.0.0.1:8080", "https://127.0.0.1:8080", "ftp://127.0.0.1",
		"http://127.0.0.1:8080/other", "http://127.0.0.1:8080/?x=1", "127.0.0.1:8080", "",
	} {
		if _, err := ValidateLocalURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
