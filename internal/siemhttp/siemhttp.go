// Package siemhttp builds the HTTP clients collectors use to reach SIEM APIs:
// proxy settings from the environment (HTTPS_PROXY/NO_PROXY), TLS 1.2+, and
// an optional CA bundle for on-prem appliances with a private or self-signed
// certificate.
package siemhttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Options configures a SIEM HTTP client.
type Options struct {
	// InsecureSkipVerify disables certificate verification. Only meant for
	// on-prem appliances with self-signed certificates; prefer CAFile.
	InsecureSkipVerify bool

	// CAFile is an optional PEM bundle trusted in addition to the system roots.
	CAFile string

	// Timeout bounds each request, including reading the body (0 = no limit).
	Timeout time.Duration
}

// NewClient returns an HTTP client configured from opts.
func NewClient(opts Options) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CAFile != "" {
		pool, err := loadCertPool(opts.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	if opts.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // explicit opt-in for self-signed on-prem appliances
	}
	transport.TLSClientConfig = tlsConfig

	return &http.Client{Timeout: opts.Timeout, Transport: transport}, nil
}

// loadCertPool returns the system roots plus the certificates in caFile.
func loadCertPool(caFile string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading ca_cert_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("ca_cert_file %s contains no PEM certificates", caFile)
	}
	return pool, nil
}

// IsCertificateError reports whether err is a TLS certificate verification
// failure (unknown authority, hostname mismatch, expired certificate...).
func IsCertificateError(err error) bool {
	if err == nil {
		return false
	}
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &verifyErr) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidErr)
}
