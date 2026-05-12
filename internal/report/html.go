package report

import (
	"html/template"
	"os"
	"time"

	"argos/internal/models"
)

type HTMLExporter struct{}

// Template HTML "God Eye" intégré dans le binaire
const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ARGOS PANOPTES - Mission Report</title>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: 'Courier New', Courier, monospace; margin: 0; padding: 20px; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .stats { background-color: #161b22; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #30363d; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background-color: #21262d; color: #8b949e; }
        .risk-high { color: #f85149; font-weight: bold; }
        .risk-med { color: #d29922; }
        .risk-low { color: #3fb950; }
        .banner { color: #8b949e; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>👁️ ARGOS Tactical Report</h1>
    <div class="stats">
        <p><strong>Generated:</strong> {{ .Time }}</p>
        <p><strong>Total Vectors Identified:</strong> {{ .Count }}</p>
    </div>
    <table>
        <tr>
            <th>TARGET</th>
            <th>PORT</th>
            <th>SERVICE</th>
            <th>THREAT INTEL</th>
            <th>IDENTITY (BANNER / WEB)</th>
        </tr>
        {{ range .Results }}
        <tr>
            <td>{{ .IP }}</td>
            <td><strong>{{ .Port }}</strong></td>
            <td>{{ .Service }}</td>
            <td>
                {{ if ge .RiskScore 20 }}<span class="risk-high">CRITICAL</span>
                {{ else if ge .RiskScore 10 }}<span class="risk-med">HIGH</span>
                {{ else }}<span class="risk-low">LOW</span>{{ end }}
            </td>
            <td class="banner">
                {{ if .WebTitle }}<strong>[{{ .WebTitle }}]</strong><br>{{ end }}
                {{ .Banner }}
            </td>
        </tr>
        {{ end }}
    </table>
</body>
</html>
`

func (e *HTMLExporter) Export(results []*models.ScanResult, filepath string) error {
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	data := struct {
		Time    string
		Count   int
		Results []*models.ScanResult
	}{
		Time:    time.Now().Format(time.RFC1123Z),
		Count:   len(results),
		Results: results,
	}

	// Execution du template (échappement automatique des caractères HTML dangereux)
	return t.Execute(f, data)
}
