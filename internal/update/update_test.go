package update

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckLatestOK(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"tag_name":"v9.9.9","html_url":"https://github.com/BVisagie/network-sweeper/releases/tag/v9.9.9"}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	res := CheckLatest(context.Background(), client)
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if !res.UpdateAvailable || res.Latest != "9.9.9" {
		t.Fatalf("%#v", res)
	}
	if !strings.Contains(res.Message, "newer") {
		t.Fatal(res.Message)
	}
}

func TestCheckLatest404(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
			Header:     make(http.Header),
		}, nil
	})}
	res := CheckLatest(context.Background(), client)
	if res.Error == "" || !strings.Contains(res.Error, "No public releases") {
		t.Fatalf("%#v", res)
	}
}

func TestCheckLatestTransportError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, io.EOF
	})}
	res := CheckLatest(context.Background(), client)
	if res.Error == "" || !strings.Contains(res.Error, "Couldn’t reach GitHub") {
		t.Fatalf("%#v", res)
	}
}
