// Package detector scores response observations against fingerprints.
package detector

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"wafrecon/internal/fingerprint"
	"wafrecon/internal/scanner"
	"wafrecon/internal/utils"
)

// Evidence explains one unique matched rule.
type Evidence struct{ Source, Key, Value, Description string }

// Result is a scored technology candidate.
type Result struct {
	Name, Category  string
	ConfidenceScore int
	ConfidenceLevel string
	Evidence        []Evidence
}

// Detect evaluates all redirect and final responses and returns ranked non-zero results.
func Detect(resp scanner.Response, db []fingerprint.Fingerprint) []Result {
	results := []Result{}
	for _, fp := range db {
		score, seen, evidence := 0, map[string]bool{}, []Evidence{}
		for _, step := range resp.Steps {
			for _, rule := range fp.Rules {
				if seen[rule.ID] {
					continue
				}
				if ev, ok := match(rule, step); ok {
					seen[rule.ID] = true
					score += rule.Weight
					evidence = append(evidence, ev)
				}
			}
		}
		if score > 100 {
			score = 100
		}
		if score > 0 {
			results = append(results, Result{Name: fp.Name, Category: fp.Category, ConfidenceScore: score, ConfidenceLevel: ConfidenceLevel(score), Evidence: evidence})
		}
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].ConfidenceScore > results[j].ConfidenceScore })
	return results
}

func match(rule fingerprint.Rule, step scanner.Step) (Evidence, bool) {
	ev := Evidence{Source: string(rule.Source), Description: rule.Description}
	switch rule.Source {
	case fingerprint.SourceHeader:
		for key, values := range step.Header {
			if strings.EqualFold(key, rule.Key) && rule.Regex.MatchString(strings.Join(values, ", ")) {
				ev.Key, ev.Value = http.CanonicalHeaderKey(key), utils.RedactHeader(key, strings.Join(values, ", "))
				return ev, true
			}
		}
	case fingerprint.SourceHeaderValue:
		for key, values := range step.Header {
			if (rule.Key == "" || strings.EqualFold(key, rule.Key)) && rule.Regex.MatchString(strings.Join(values, ", ")) {
				ev.Key, ev.Value = http.CanonicalHeaderKey(key), utils.RedactHeader(key, strings.Join(values, ", "))
				return ev, true
			}
		}
	case fingerprint.SourceCookie:
		for _, raw := range step.Header.Values("Set-Cookie") {
			name := strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
			if rule.Regex.MatchString(name) {
				ev.Key, ev.Value = name, "[REDACTED]"
				return ev, true
			}
		}
	case fingerprint.SourceBody:
		if rule.Regex.Match(step.Body) {
			ev.Key, ev.Value = "body", "[MATCHED CONTENT REDACTED]"
			return ev, true
		}
	case fingerprint.SourceStatus:
		if rule.Regex.MatchString(strconv.Itoa(step.StatusCode)) {
			ev.Key, ev.Value = "status", strconv.Itoa(step.StatusCode)
			return ev, true
		}
	}
	return Evidence{}, false
}

// ConfidenceLevel maps a numeric score to its documented label.
func ConfidenceLevel(score int) string {
	switch {
	case score >= 80:
		return "Very High"
	case score >= 60:
		return "High"
	case score >= 40:
		return "Medium"
	case score >= 20:
		return "Low"
	default:
		return "Inconclusive"
	}
}
func (e Evidence) String() string { return fmt.Sprintf("%s %s: %s", e.Source, e.Key, e.Description) }
