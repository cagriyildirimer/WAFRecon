package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("0123456789")) }))
	defer server.Close()
	got, err := Scan(server.Client(), server.URL, "test", nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Steps[0].Body) != "0123" {
		t.Fatalf("body=%q", got.Steps[0].Body)
	}
}
