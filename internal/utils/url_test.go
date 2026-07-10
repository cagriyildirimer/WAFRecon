package utils

import "testing"

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input, want string
		bad         bool
	}{{"example.com", "https://example.com", false}, {"https://example.com/a", "https://example.com/a", false}, {"", "", true}, {"file:///etc/passwd", "", true}, {"ftp://example.com", "", true}, {"http://", "", true}}
	for _, tt := range tests {
		got, err := NormalizeURL(tt.input)
		if (err != nil) != tt.bad || (!tt.bad && got != tt.want) {
			t.Errorf("NormalizeURL(%q)=(%q,%v)", tt.input, got, err)
		}
	}
}
func TestRedactHeader(t *testing.T) {
	for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-API-Key", "X-Access-Token"} {
		if got := RedactHeader(key, "secret"); got != "[REDACTED]" {
			t.Errorf("%s leaked", key)
		}
	}
}
