package report

import (
	"fmt"
	"html/template"
	"os"
	"time"
)

// ReportData holds all the data to be rendered in the HTML report
type ReportData struct {
	Target          string
	Date            string
	Duration        string
	Vulnerabilities []Vulnerability
	Assets          []Asset
	Stats           Stats
}

// Vulnerability represents a single finding
type Vulnerability struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Tool        string `json:"tool"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"` // Path to screenshot or raw output snippet
}

// Asset represents a discovered asset
type Asset struct {
	URL          string   `json:"url"`
	IP           string   `json:"ip"`
	Technologies []string `json:"technologies"`
	Title        string   `json:"title"`
	StatusCode   int      `json:"status_code"`
}

// Stats holds summary statistics
type Stats struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// GenerateReport generates the HTML report from the scan results
func GenerateReport(resultsDir string, outputFile string, target string) error {
	// 1. Parse results from various tools
	vulns, assets, err := parseResults(resultsDir)
	if err != nil {
		return fmt.Errorf("failed to parse results: %w", err)
	}

	// 2. Calculate stats
	stats := calculateStats(vulns)

	// 3. Prepare data
	data := ReportData{
		Target:          target,
		Date:            time.Now().Format("2006-01-02 15:04:05"),
		Vulnerabilities: vulns,
		Assets:          assets,
		Stats:           stats,
	}

	// 4. Render template
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

func calculateStats(vulns []Vulnerability) Stats {
	stats := Stats{}
	for _, v := range vulns {
		stats.Total++
		switch v.Severity {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		case "low":
			stats.Low++
		default:
			stats.Info++
		}
	}
	return stats
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedRecon Report - {{.Target}}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }
        header { background-color: #2c3e50; color: #fff; padding: 20px; text-align: center; }
        .container { padding: 20px; max-width: 1200px; margin: 0 auto; }
        .summary { display: flex; justify-content: space-around; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stat-box { text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #3498db; }
        .info { color: #95a5a6; }
        .section-title { border-bottom: 2px solid #2c3e50; padding-bottom: 10px; margin-bottom: 20px; margin-top: 40px; }
        table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: #fff; }
        tr:hover { background-color: #f1f1f1; }
        .severity-badge { padding: 5px 10px; border-radius: 4px; color: #fff; font-size: 0.8em; text-transform: uppercase; }
        .bg-critical { background-color: #e74c3c; }
        .bg-high { background-color: #e67e22; }
        .bg-medium { background-color: #f1c40f; }
        .bg-low { background-color: #3498db; }
        .bg-info { background-color: #95a5a6; }
    </style>
</head>
<body>
    <header>
        <h1>RedRecon Scan Report</h1>
        <p>Target: {{.Target}} | Date: {{.Date}}</p>
    </header>

    <div class="container">
        <div class="summary">
            <div class="stat-box"><div class="stat-value critical">{{.Stats.Critical}}</div><div>Critical</div></div>
            <div class="stat-box"><div class="stat-value high">{{.Stats.High}}</div><div>High</div></div>
            <div class="stat-box"><div class="stat-value medium">{{.Stats.Medium}}</div><div>Medium</div></div>
            <div class="stat-box"><div class="stat-value low">{{.Stats.Low}}</div><div>Low</div></div>
            <div class="stat-box"><div class="stat-value info">{{.Stats.Info}}</div><div>Info</div></div>
            <div class="stat-box"><div class="stat-value">{{.Stats.Total}}</div><div>Total</div></div>
        </div>

        <h2 class="section-title">Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Tool</th>
                    <th>URL</th>
                </tr>
            </thead>
            <tbody>
                {{range .Vulnerabilities}}
                <tr>
                    <td><span class="severity-badge bg-{{.Severity}}">{{.Severity}}</span></td>
                    <td>{{.Title}}</td>
                    <td>{{.Tool}}</td>
                    <td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <h2 class="section-title">Discovered Assets</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>IP</th>
                    <th>Tech</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {{range .Assets}}
                <tr>
                    <td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
                    <td>{{.IP}}</td>
                    <td>{{range .Technologies}}{{.}}, {{end}}</td>
                    <td>{{.StatusCode}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>
`
