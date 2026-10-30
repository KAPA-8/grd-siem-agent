package siemhttp

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

func writeServerCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func get(t *testing.T, client *http.Client, url string) error {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func TestNewClient_VerifiesByDefault(t *testing.T) {
	server := newTLSServer(t)
	client, err := NewClient(Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = get(t, client, server.URL)
	if err == nil {
		t.Fatal("expected a certificate error against a self-signed server")
	}
	if !IsCertificateError(err) {
		t.Errorf("IsCertificateError(%v) = false, want true", err)
	}
}

func TestNewClient_SkipVerify(t *testing.T) {
	server := newTLSServer(t)
	client, err := NewClient(Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, client, server.URL); err != nil {
		t.Fatalf("skip-verify request failed: %v", err)
	}
}

func TestNewClient_CAFile(t *testing.T) {
	server := newTLSServer(t)
	client, err := NewClient(Options{CAFile: writeServerCA(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, client, server.URL); err != nil {
		t.Fatalf("request with the server CA failed: %v", err)
	}
}

func TestNewClient_CAFileErrors(t *testing.T) {
	if _, err := NewClient(Options{CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil || !strings.Contains(err.Error(), "reading ca_cert_file") {
		t.Errorf("missing file: err = %v", err)
	}
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(Options{CAFile: garbage}); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Errorf("garbage file: err = %v", err)
	}
}

func TestNewClient_ProxyAndTLSSettings(t *testing.T) {
	client, err := NewClient(Options{Timeout: 7 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy == nil {
		t.Error("Proxy must be set (ProxyFromEnvironment)")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion == 0 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("unexpected TLS config: %+v", transport.TLSClientConfig)
	}
	if client.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v", client.Timeout)
	}
	// The shared default transport must not be modified.
	if http.DefaultTransport.(*http.Transport).TLSClientConfig == transport.TLSClientConfig {
		t.Error("default transport TLS config was shared")
	}
}

func TestIsCertificateError_Other(t *testing.T) {
	if IsCertificateError(nil) || IsCertificateError(errors.New("connection refused")) {
		t.Error("non-certificate errors must return false")
	}
}
