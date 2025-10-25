package scan

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/logrusorgru/aurora"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// StartScan initializes a vulnerability scan using Nuclei.
func StartScan(target, templateFilter string) {
	slog.Info("Starting Nuclei scan", "target", target, "template_filter", templateFilter)

	// --- Nuclei Integration ---
	targetName := filepath.Base(target)
	resultsPath := filepath.Join("results", targetName, "scan")
	_ = os.MkdirAll(resultsPath, 0755)
	outputFile := filepath.Join(resultsPath, "nuclei_findings.txt")

	// Configure output writer for text file (no JSON, no colors).
	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		slog.Error("Could not open output file", "error", err)
		return
	}
	defer f.Close()

	writer, err := output.NewWriter(
		output.WithWriter(f),
		output.WithAurora(aurora.NewAurora(false)), // Disable colors for file output.
	)
	if err != nil {
		slog.Error("Could not create output writer", "error", err)
		return
	}

	// Configure Nuclei options, including the output writer callback.
	var opts []nuclei.NucleiSDKOptions
	opts = append(opts, nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}))

	if templateFilter != "default" {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templateFilter}}))
	}

	ne, err := nuclei.NewNucleiEngine(opts...)
	if err != nil {
		slog.Error("Could not create nuclei engine", "error", err)
		return
	}
	defer ne.Close()
	// Load targets and execute the scan.
	ne.LoadTargets([]string{target}, true)

	// Execute the scan.
	callback := func(event *output.ResultEvent) {
		// Handle the error from the writer internally, as the callback signature doesn't return one.
		_ = writer.Write(event)
	}
	if err := ne.ExecuteWithCallback(callback); err != nil {
		slog.Error("Error during nuclei execution", "error", err)
	}

	slog.Info("Nuclei scan finished.", "results_file", outputFile)
	fmt.Printf("Nuclei scan finished. Results saved to %s\n", outputFile)
}