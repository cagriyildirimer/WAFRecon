# WAFRecon

WAFRecon is a passive Go command-line tool that estimates the WAF, CDN, and reverse proxy technologies used by a target. It inspects response headers, cookies, status codes, redirect responses, and a bounded portion of the response body from a single normal HTTP GET request. It does not send exploits, bypass attempts, brute-force traffic, or attack payloads.

## Features

- Weighted, deduplicated confidence scoring capped at 100
- Detection of multiple technologies in the same response
- Inspection of intermediate redirect responses and automatic decompression
- Configurable timeout, TLS verification, redirects, User-Agent, request headers, and body limit
- Redaction of sensitive headers and all cookie values
- Machine-readable output that emits valid JSON only
- No external services, TLS certificate analysis, or ASN lookups

## Installation and build

Go 1.24 or later is required.

```sh
go install ./cmd/wafrecon
go build -o wafrecon ./cmd/wafrecon
go test ./...
```

## Usage

```sh
wafrecon https://example.com
wafrecon --url https://example.com --verbose
wafrecon -u example.com --timeout 5s --json
wafrecon -H 'Accept-Language: tr' --redirects=false example.com
```

Options: `-u, --url`, `-t, --timeout` (10s), `-k, --insecure`, `-r, --redirects`, `-a, --user-agent`, repeatable `-H, --header`, `-v, --verbose`, `--json`, `--body-limit` (1 MiB), `--version`, and `--help`.

## Example terminal output

```text
Target: https://example.com
Status: 403 Forbidden
Final URL: https://example.com
Response Time: 241 ms

Detected:
[+] Cloudflare
Confidence: 100/100 - Very High
```

## Example JSON output

```json
{"target":"https://example.com","final_url":"https://example.com","status_code":403,"response_time_ms":241,"technologies":[{"name":"Cloudflare","category":"WAF/CDN","confidence_score":80,"confidence_level":"Very High","evidence":[{"source":"header","key":"Cf-Ray","value":"abc123"}]}],"errors":[]}
```

## Supported technologies

Cloudflare, Akamai, F5 BIG-IP/ASM/Advanced WAF, Imperva/Incapsula, AWS WAF/CloudFront, Azure Front Door/Application Gateway, Fastly, Sucuri, Barracuda WAF, FortiWeb, Citrix NetScaler/ADC, Radware, StackPath, Varnish, Nginx, HAProxy, ModSecurity, and generic WAF/reverse proxy indicators.

## Adding a fingerprint

Add the product to `DefaultDatabase` in `internal/fingerprint/database.go`. Each rule should have a unique ID, source (`header`, `header_value`, `cookie`, or `body`), case-insensitive regular expression, weight, and evidence description. Regular expressions are compiled once at startup. Give strong product-specific indicators more weight than generic signals, and add a table-driven test for every new fingerprint.

## Limitations and responsible use

Fingerprint results are probabilistic, so false positives and false negatives are possible. A lack of conclusive results does not prove that the target has no WAF or CDN. Use WAFRecon only on systems you own or have explicit permission to test. You are responsible for complying with all applicable laws, policies, and authorization boundaries.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
