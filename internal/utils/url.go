// Package utils contains input validation and redaction helpers.
package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeURL validates a target, adding HTTPS when its scheme is omitted.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("target URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", u.Scheme)
	}
	if u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("invalid HTTP URL")
	}
	return u.String(), nil
}

// RedactHeader masks values likely to contain credentials or session data.
func RedactHeader(key, value string) string {
	lower := strings.ToLower(key)
	switch lower {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return "[REDACTED]"
	}
	if lower == "x-api-key" || lower == "api-key" || strings.Contains(lower, "auth-token") || strings.Contains(lower, "access-token") {
		return "[REDACTED]"
	}
	return value
}
