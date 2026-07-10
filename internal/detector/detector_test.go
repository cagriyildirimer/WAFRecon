package detector

import (
	"net/http"
	"regexp"
	"testing"

	"wafrecon/internal/fingerprint"
	"wafrecon/internal/scanner"
)

func response(header http.Header, body string) scanner.Response {
	return scanner.Response{Steps: []scanner.Step{{Header: header, Body: []byte(body)}}}
}
func find(results []Result, name string) *Result {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

func TestBuiltInDetection(t *testing.T) {
	tests := []struct {
		name, product string
		header        http.Header
	}{
		{"cloudflare", "Cloudflare", http.Header{"Cf-Ray": {"abc"}}},
		{"case insensitive Cloudflare", "Cloudflare", http.Header{"cF-rAy": {"abc"}}},
		{"akamai", "Akamai", http.Header{"Akamai-Grn": {"abc"}}},
		{"f5 cookie", "F5 BIG-IP / ASM / Advanced WAF", http.Header{"Set-Cookie": {"BIGipServerPool=secret; Path=/"}}},
		{"imperva cookie", "Imperva / Incapsula", http.Header{"Set-Cookie": {"visid_incap_1=secret"}}},
		{"cloudfront", "AWS CloudFront / AWS WAF", http.Header{"X-Amz-Cf-Id": {"secret"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if find(Detect(response(tt.header, ""), fingerprint.DefaultDatabase()), tt.product) == nil {
				t.Fatalf("expected %s", tt.product)
			}
		})
	}
}

func TestMultipleTechnologies(t *testing.T) {
	results := Detect(response(http.Header{"Cf-Ray": {"x"}, "Server": {"nginx"}}, ""), fingerprint.DefaultDatabase())
	if find(results, "Cloudflare") == nil || find(results, "Nginx") == nil {
		t.Fatal("expected both Cloudflare and Nginx")
	}
}
func TestNoFingerprint(t *testing.T) {
	if got := Detect(response(http.Header{}, "ordinary page"), fingerprint.DefaultDatabase()); len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
}

func TestScoreCapAndDeduplication(t *testing.T) {
	fp := fingerprint.Fingerprint{Name: "Test", Rules: []fingerprint.Rule{{ID: "unique", Source: fingerprint.SourceHeader, Key: "X-Test", Weight: 150, Regex: regexp.MustCompile(`.+`)}}}
	r := scanner.Response{Steps: []scanner.Step{{Header: http.Header{"X-Test": {"a"}}}, {Header: http.Header{"X-Test": {"b"}}}}}
	got := Detect(r, []fingerprint.Fingerprint{fp})
	if got[0].ConfidenceScore != 100 || len(got[0].Evidence) != 1 {
		t.Fatalf("score=%d evidence=%d", got[0].ConfidenceScore, len(got[0].Evidence))
	}
}

func TestSensitiveEvidenceRedacted(t *testing.T) {
	got := Detect(response(http.Header{"Set-Cookie": {"__cf_bm=topsecret"}}, ""), fingerprint.DefaultDatabase())
	cf := find(got, "Cloudflare")
	if cf == nil || cf.Evidence[0].Value != "[REDACTED]" {
		t.Fatalf("not redacted: %#v", cf)
	}
}
