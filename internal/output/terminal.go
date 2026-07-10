// Package output renders WAFRecon reports.
package output

import (
	"fmt"
	"io"

	"wafrecon/internal/detector"
	"wafrecon/internal/scanner"
)

// Terminal writes the human-readable report.
func Terminal(w io.Writer, response scanner.Response, results []detector.Result, verbose bool) {
	fmt.Fprintf(w, "Target: %s\nStatus: %s\nFinal URL: %s\nResponse Time: %d ms\n\n", response.Target, response.Status, response.FinalURL, response.ResponseTime.Milliseconds())
	conclusive := false
	for _, result := range results {
		if result.ConfidenceScore < 20 {
			continue
		}
		conclusive = true
		label := "Possible"
		marker := "[~]"
		if result.ConfidenceScore >= 40 {
			label, marker = "Detected", "[+]"
		}
		fmt.Fprintf(w, "%s:\n%s %s\nConfidence: %d/100 - %s\n", label, marker, result.Name, result.ConfidenceScore, result.ConfidenceLevel)
		if verbose {
			fmt.Fprintln(w, "Evidence:")
			for _, ev := range result.Evidence {
				fmt.Fprintf(w, "* %s\n", ev.String())
			}
		}
		fmt.Fprintln(w)
	}
	if !conclusive {
		fmt.Fprintln(w, "[-] No conclusive WAF or CDN fingerprint detected.\nNote: This does not prove that the target has no WAF or CDN.")
	}
}
