// Package fingerprint defines the extensible fingerprint database.
package fingerprint

import "regexp"

// Source identifies the response field inspected by a rule.
type Source string

const (
	SourceHeader      Source = "header"
	SourceHeaderValue Source = "header_value"
	SourceCookie      Source = "cookie"
	SourceBody        Source = "body"
	SourceStatus      Source = "status"
)

// Rule is one independently scored response signature.
type Rule struct {
	ID, Key, Pattern, Description string
	Source                        Source
	Weight                        int
	Sensitive                     bool
	Regex                         *regexp.Regexp
}

// Fingerprint describes one product and its positive and negative signatures.
type Fingerprint struct {
	Name, Category string
	Rules          []Rule
	Negative       []*regexp.Regexp
}
