package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"wafrecon/internal/detector"
	"wafrecon/internal/scanner"
)

func TestJSONValidAndRedacted(t *testing.T) {
	var b bytes.Buffer
	response := scanner.Response{Target: "https://example.com"}
	results := []detector.Result{{Name: "Test", Evidence: []detector.Evidence{{Source: "cookie", Key: "sid", Value: "[REDACTED]"}}}}
	if err := JSON(&b, response, results, []string{}); err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(b.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte("secret")) {
		t.Fatal("secret leaked")
	}
}
