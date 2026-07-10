package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"wafrecon/internal/detector"
	"wafrecon/internal/fingerprint"
	"wafrecon/internal/httpclient"
	"wafrecon/internal/output"
	"wafrecon/internal/scanner"
	"wafrecon/internal/utils"
)

const version = "0.1.0"

type headersFlag []string

func (h *headersFlag) String() string { return strings.Join(*h, ",") }
func (h *headersFlag) Set(v string) error {
	if !strings.Contains(v, ":") {
		return fmt.Errorf("header must be in 'Name: value' format")
	}
	*h = append(*h, v)
	return nil
}

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	fs := flag.NewFlagSet("wafrecon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var target, ua string
	var timeout time.Duration
	var insecure, redirects, verbose, asJSON, showVersion bool
	var bodyLimit int64
	var custom headersFlag
	fs.StringVar(&target, "url", "", "target URL")
	fs.StringVar(&target, "u", "", "target URL")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "request timeout")
	fs.DurationVar(&timeout, "t", 10*time.Second, "request timeout")
	fs.BoolVar(&insecure, "insecure", false, "accept invalid TLS certificates")
	fs.BoolVar(&insecure, "k", false, "accept invalid TLS certificates")
	fs.BoolVar(&redirects, "redirects", true, "follow redirects")
	fs.BoolVar(&redirects, "r", true, "follow redirects")
	fs.StringVar(&ua, "user-agent", "WAFRecon/"+version, "User-Agent")
	fs.StringVar(&ua, "a", "WAFRecon/"+version, "User-Agent")
	fs.Var(&custom, "header", "custom request header (repeatable)")
	fs.Var(&custom, "H", "custom request header (repeatable)")
	fs.BoolVar(&verbose, "verbose", false, "show matched evidence")
	fs.BoolVar(&verbose, "v", false, "show matched evidence")
	fs.BoolVar(&asJSON, "json", false, "output JSON only")
	fs.Int64Var(&bodyLimit, "body-limit", 1024*1024, "maximum response body bytes")
	fs.BoolVar(&showVersion, "version", false, "show version")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: wafrecon [options] <URL>\n\nPassive HTTP fingerprinting for WAF, CDN and reverse proxies.\n\nOptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Println("WAFRecon " + version)
		return 0
	}
	if target == "" && fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	normalized, err := utils.NormalizeURL(target)
	if err != nil {
		return fail(asJSON, scanner.Response{Target: target}, err)
	}
	if timeout <= 0 || bodyLimit < 0 {
		return fail(asJSON, scanner.Response{Target: normalized}, fmt.Errorf("timeout must be positive and body-limit cannot be negative"))
	}
	headers := make(http.Header)
	for _, item := range custom {
		parts := strings.SplitN(item, ":", 2)
		name, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if name == "" || strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return fail(asJSON, scanner.Response{Target: normalized}, fmt.Errorf("invalid custom header"))
		}
		headers.Add(name, value)
	}
	client := httpclient.New(httpclient.Config{Timeout: timeout, Insecure: insecure, Redirects: redirects, MaxRedirects: 10})
	response, err := scanner.Scan(client, normalized, ua, headers, bodyLimit)
	if err != nil {
		return fail(asJSON, response, fmt.Errorf("request failed: %w", err))
	}
	results := detector.Detect(response, fingerprint.DefaultDatabase())
	if asJSON {
		if err := output.JSON(os.Stdout, response, results, []string{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else {
		output.Terminal(os.Stdout, response, results, verbose)
	}
	return 0
}
func fail(asJSON bool, response scanner.Response, err error) int {
	if asJSON {
		_ = output.JSON(os.Stdout, response, nil, []string{err.Error()})
	} else {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
	return 1
}
