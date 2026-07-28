package enrich

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/BVisagie/network-sweeper/internal/scan"
)

func TestExtractTitle(t *testing.T) {
	got := extractTitle("<html><head><title>  Synology DSM  </title></head></html>")
	if got != "Synology DSM" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeLineStopsAtNewline(t *testing.T) {
	got := sanitizeLine("SSH-2.0-OpenSSH_9.0\r\nextra")
	if got != "SSH-2.0-OpenSSH_9.0" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeLineDecodesEntities(t *testing.T) {
	got := sanitizeLine(`32&quot; Odyssey OLED G8`)
	if got != `32" Odyssey OLED G8` {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityHint(t *testing.T) {
	hint := IdentityHint([]scan.OpenPort{
		{Port: 443, TLSCommonName: "router.local"},
		{Port: 80, HTTPTitle: "Router Login"},
	})
	if hint != "Router Login" {
		t.Fatalf("got %q", hint)
	}
}

func TestResultsHTTPAndTLS(t *testing.T) {
	lnHTTP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnHTTP.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		fmt.Fprint(w, "<html><title>Probe Target</title></html>")
	})
	go http.Serve(lnHTTP, mux)

	certPEM, keyPEM := mustSelfSigned(t, "probe.local")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lnTLS, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer lnTLS.Close()
	go http.Serve(lnTLS, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html><title>Secure UI</title></html>")
	}))

	httpPort := lnHTTP.Addr().(*net.TCPAddr).Port
	tlsPort := lnTLS.Addr().(*net.TCPAddr).Port

	// Temporarily treat these dynamic ports as enrichable by calling probes directly.
	opHTTP := scan.OpenPort{Port: httpPort, Service: "HTTP"}
	opTLS := scan.OpenPort{Port: tlsPort, Service: "HTTPS"}
	ctx := context.Background()
	probeHTTP(ctx, "127.0.0.1", &opHTTP, time.Second, false)
	probeTLS(ctx, "127.0.0.1", &opTLS, time.Second)
	probeHTTP(ctx, "127.0.0.1", &opTLS, time.Second, true)

	if opHTTP.HTTPTitle != "Probe Target" {
		t.Fatalf("http title: %q", opHTTP.HTTPTitle)
	}
	if opHTTP.HTTPServer != "TestServer/1.0" {
		t.Fatalf("http server: %q", opHTTP.HTTPServer)
	}
	if opTLS.TLSCommonName != "probe.local" {
		t.Fatalf("tls cn: %q", opTLS.TLSCommonName)
	}
	if !opTLS.TLSSelfSigned {
		t.Fatal("expected self-signed")
	}
	if opTLS.HTTPTitle != "Secure UI" {
		t.Fatalf("https title: %q", opTLS.HTTPTitle)
	}
}

func TestResultsBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	}()

	op := scan.OpenPort{Port: ln.Addr().(*net.TCPAddr).Port, Service: "SSH"}
	probeBanner(context.Background(), "127.0.0.1", &op, time.Second)
	if op.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("banner: %q", op.Banner)
	}
}

func mustSelfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
