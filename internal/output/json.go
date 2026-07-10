package output

import (
	"encoding/json"
	"io"

	"wafrecon/internal/detector"
	"wafrecon/internal/scanner"
)

type jsonEvidence struct {
	Source string `json:"source"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}
type jsonTechnology struct {
	Name            string         `json:"name"`
	Category        string         `json:"category"`
	ConfidenceScore int            `json:"confidence_score"`
	ConfidenceLevel string         `json:"confidence_level"`
	Evidence        []jsonEvidence `json:"evidence"`
}
type jsonReport struct {
	Target         string           `json:"target"`
	FinalURL       string           `json:"final_url"`
	StatusCode     int              `json:"status_code"`
	ResponseTimeMS int64            `json:"response_time_ms"`
	Technologies   []jsonTechnology `json:"technologies"`
	Errors         []string         `json:"errors"`
}

// JSON writes only a valid JSON document.
func JSON(w io.Writer, response scanner.Response, results []detector.Result, errors []string) error {
	report := jsonReport{Target: response.Target, FinalURL: response.FinalURL, StatusCode: response.StatusCode, ResponseTimeMS: response.ResponseTime.Milliseconds(), Technologies: []jsonTechnology{}, Errors: errors}
	for _, result := range results {
		technology := jsonTechnology{Name: result.Name, Category: result.Category, ConfidenceScore: result.ConfidenceScore, ConfidenceLevel: result.ConfidenceLevel, Evidence: []jsonEvidence{}}
		for _, evidence := range result.Evidence {
			technology.Evidence = append(technology.Evidence, jsonEvidence{Source: evidence.Source, Key: evidence.Key, Value: evidence.Value})
		}
		report.Technologies = append(report.Technologies, technology)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
