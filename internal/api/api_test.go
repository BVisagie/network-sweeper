package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
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
