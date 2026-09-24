package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/BVisagie/network-sweeper/internal/discover"
)

func testFS() fs.FS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!doctype html><html><body>token=__SESSION_TOKEN__ v=__APP_VERSION__</body></html>`)},
		"app.js":     &fstest.MapFile{Data: []byte(`console.log('ok')`)},
		"style.css":  &fstest.MapFile{Data: []byte(`body{}`)},
	}
}

func TestTokenRequired(t *testing.T) {
	s := New(testFS(), false)
	s.BaseURL = "http://127.0.0.1:9999"
	hs, ln, err := s.ListenAndServe()
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	defer ln.Close()

	resp, err := http.Get(s.BaseURL + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestOriginRejected(t *testing.T) {
	s := New(testFS(), false)
	s.BaseURL = "http://127.0.0.1:1"
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.Header.Set(TokenHeader, s.Token)
	req.Header.Set("Origin", "http://evil.example")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestOriginAllowed(t *testing.T) {
	s := New(testFS(), false)
	s.BaseURL = "http://127.0.0.1:12345"
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.Header.Set(TokenHeader, s.Token)
	req.Header.Set("Origin", "http://127.0.0.1:12345")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCustomCIDRRejectedWithoutOptIn(t *testing.T) {
	s := New(testFS(), false)
	s.BaseURL = "http://127.0.0.1:12345"
	body, _ := json.Marshal(scanRequest{
		Targets:     []string{"8.8.8.0/24"},
		CustomOptIn: false,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(body))
	req.Header.Set(TokenHeader, s.Token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScanCancelIdle(t *testing.T) {
	s := New(testFS(), false)
	s.BaseURL = "http://127.0.0.1:12345"
	req := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", bytes.NewReader([]byte("{}")))
	req.Header.Set(TokenHeader, s.Token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCSVEscape(t *testing.T) {
	snap := &ScanSnapshot{
		Hosts: []discover.Host{{
			IP: "10.0.0.2", MAC: "aa:bb:cc:dd:ee:ff",
			Vendor: `Acme, "Inc"`, Hostname: "host\nname",
			AliveVia: []string{"tcp/80"},
		}},
	}
	out := exportCSV(snap)
	if !strings.Contains(out, `"Acme, ""Inc"""`) {
		t.Fatalf("vendor quoting: %s", out)
	}
	if !strings.Contains(out, `"host\nname"`) && !strings.Contains(out, "host") {
		t.Fatalf("hostname: %s", out)
	}
}

// Names, titles and banners come from devices on the network, so an export
// must never hand a spreadsheet a formula or hidden text-direction tricks.
func TestCSVFieldNeutralisesDeviceText(t *testing.T) {
	for in, want := range map[string]string{
		"=HYPERLINK(\"http://x\")": `"'=HYPERLINK(""http://x"")"`,
		"+1+1":                     "'+1+1",
		"-2+3":                     "'-2+3",
		"@SUM(A1)":                 "'@SUM(A1)",
		"\t=1+1":                   " =1+1",
		"evil\u202Etxt.exe":        "eviltxt.exe",
		"line1\nline2":             "line1 line2",
		"Acme, Inc.":               `"Acme, Inc."`,
		"plain":                    "plain",
	} {
		if got := csvField(in); got != want {
			t.Errorf("csvField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIndexInjectsToken(t *testing.T) {
	s := New(testFS(), false)
	s.BaseURL = "http://127.0.0.1:12345"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(s.Token)) {
		t.Fatal("token not injected")
	}
}

func TestReserveScanAdmitsOne(t *testing.T) {
	s := New(testFS(), false)
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	nets := []*net.IPNet{lan}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.reserveScan(&scanPlan{targets: nets}, nets, false); err == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	s.cancelScan()
	if n := admitted.Load(); n != 1 {
		t.Fatalf("admitted %d scans, want 1", n)
	}
}
