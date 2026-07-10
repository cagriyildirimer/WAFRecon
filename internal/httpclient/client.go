// Package httpclient constructs the bounded HTTP client used by WAFRecon.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"

	"wafrecon/internal/scanner"
)

// Config controls network safety and redirect behavior.
type Config struct {
	Timeout             time.Duration
	Insecure, Redirects bool
	MaxRedirects        int
}

// New constructs a client with explicit TLS, timeout, decompression and redirect settings.
func New(cfg Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure} // #nosec G402 -- explicitly requested CLI option.
	client := &http.Client{Timeout: cfg.Timeout, Transport: transport}
	if cfg.Redirects {
		client.CheckRedirect = scanner.RedirectRecorder(cfg.MaxRedirects)
	} else {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return client
}
