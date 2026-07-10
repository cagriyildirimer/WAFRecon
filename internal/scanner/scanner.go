// Package scanner collects bounded HTTP response observations.
package scanner

import (
	"context"
	"io"
	"net/http"
	"time"
)

// Response contains the final response and every response in the redirect chain.
type Response struct {
	Target, FinalURL string
	StatusCode       int
	Status           string
	ResponseTime     time.Duration
	Steps            []Step
}

// Step is one HTTP response observation.
type Step struct {
	URL        string
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Scan performs exactly one logical GET, including configured redirects.
func Scan(client *http.Client, target, userAgent string, headers http.Header, bodyLimit int64) (Response, error) {
	start := time.Now()
	steps := []Step{}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, values := range headers {
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	req = req.WithContext(context.WithValue(req.Context(), stepsKey{}, &steps))
	resp, err := client.Do(req)
	if err != nil {
		return Response{Target: target, ResponseTime: time.Since(start)}, err
	}
	defer resp.Body.Close()
	body, err := readBounded(resp.Body, bodyLimit)
	if err != nil {
		return Response{}, err
	}
	chain := []Step{}
	chain = append(chain, steps...)
	chain = append(chain, Step{URL: resp.Request.URL.String(), StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: body})
	return Response{Target: target, FinalURL: resp.Request.URL.String(), StatusCode: resp.StatusCode, Status: resp.Status, ResponseTime: time.Since(start), Steps: chain}, nil
}

// RedirectRecorder returns a CheckRedirect callback that records intermediate responses.
func RedirectRecorder(max int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= max {
			return http.ErrUseLastResponse
		}
		if len(via) > 0 {
			steps, _ := via[0].Context().Value(stepsKey{}).(*[]Step)
			prev := via[len(via)-1].Response
			if steps != nil && prev != nil {
				*steps = append(*steps, Step{URL: prev.Request.URL.String(), StatusCode: prev.StatusCode, Header: prev.Header.Clone()})
			}
		}
		return nil
	}
}

type stepsKey struct{}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		limit = 0
	}
	return io.ReadAll(io.LimitReader(r, limit))
}
