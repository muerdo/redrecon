package cloud

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"redrecon/pkg/utils"
)

// DumpConfig defines the configuration for the asset dumper.
type DumpConfig struct {
	Extensions  []string
	MaxFileSize int64 // Bytes
	OutputDir   string
}

// Default extensions to dump
var DefaultInterestingExtensions = []string{
	".config", ".xml", ".json", ".sql", ".bak", ".backup", ".key", ".pem", ".p12",
	".env", ".log", ".txt", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf",
	".vmdk", ".ovf", ".ova", // VM files
}

// DownloadAsset downloads 'url' if it meets criteria (extension, size).
func DownloadAsset(urlStr string, config DumpConfig, client *http.Client) (string, error) {
	// 1. Check Extension
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	ext := strings.ToLower(filepath.Ext(parsed.Path))
	interesting := false
	for _, e := range config.Extensions {
		if ext == e {
			interesting = true
			break
		}
	}
	if !interesting {
		return "", fmt.Errorf("extension not interesting: %s", ext)
	}

	// 2. Check Head (Size)
	headReq, err := http.NewRequest("HEAD", urlStr, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(headReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}

	if resp.ContentLength > config.MaxFileSize {
		return "", fmt.Errorf("file too large: %d bytes (max: %d)", resp.ContentLength, config.MaxFileSize)
	}

	// 3. Download
	getReq, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}
	resp, err = client.Do(getReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Ensure output dir exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return "", err
	}

	filename := filepath.Base(parsed.Path)
	if filename == "" || filename == "." {
		filename = "index_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ext
	}
	// Sanitize filename
	filename = utils.SanitizeFilename(filename)

	outputPath := filepath.Join(config.OutputDir, filename)
	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}
