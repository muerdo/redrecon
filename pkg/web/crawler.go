package web

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocolly/colly/v2"
)

// ignoredExtensions defines file extensions to be ignored during crawling.
var ignoredExtensions = []string{
	".zip", ".rar", ".7z", ".tar", ".gz",
	".mp4", ".avi", ".mkv",
	".mp3", ".wav",
	".exe", ".msi", ".dmg",
	".pdf", ".doc", ".docx", ".xls", ".xlsx",
}

// CrawlWebsite downloads the assets of a website to a local folder.
func CrawlWebsite(targetURL string, maxDepth int) error {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	// Define the results directory.
	resultsDir := filepath.Join("results", parsedURL.Hostname(), "web")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	slog.Info("Saving crawled files to", "directory", resultsDir)

	// Handle www and non-www redirects by allowing both.
	allowedDomains := []string{parsedURL.Hostname()}
	if strings.HasPrefix(parsedURL.Hostname(), "www.") {
		allowedDomains = append(allowedDomains, strings.TrimPrefix(parsedURL.Hostname(), "www."))
	} else {
		allowedDomains = append(allowedDomains, "www."+parsedURL.Hostname())
	}

	c := colly.NewCollector(
		// Allow visiting the main domain and its www/non-www counterpart.
		colly.AllowedDomains(allowedDomains...),
		// Set the maximum crawl depth.
		colly.MaxDepth(maxDepth),
	)

	// Handler to find and visit links.
	c.OnHTML("a[href], link[href], script[src], img[src], source[src]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" {
			link = e.Request.AbsoluteURL(e.Attr("src"))
		}

		// Check if the file extension should be ignored.
		isIgnored := false
		for _, ext := range ignoredExtensions {
			if strings.HasSuffix(strings.ToLower(link), ext) {
				slog.Debug("Ignoring link with blacklisted extension", "link", link)
				isIgnored = true
				break
			}
		}

		if !isIgnored && link != "" {
			c.Visit(link)
		}
	})

	// Handler to save responses to disk.
	c.OnResponse(func(r *colly.Response) {
		// Ensure we are only saving content from the target domain.
		if !isAllowedDomain(r.Request.URL.Hostname(), allowedDomains) {
			return
		}

		// Create the local directory structure.
		path := filepath.Join(resultsDir, r.Request.URL.Path)
		if strings.HasSuffix(path, "/") || path == "" {
			path = filepath.Join(path, "index.html")
		}
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			slog.Error("Failed to create directory for file", "dir", dir, "error", err)
			return
		}

		// Save the response body to a file.
		err := os.WriteFile(path, r.Body, 0644)
		if err != nil {
			slog.Error("Failed to write file", "path", path, "error", err)
		} else {
			slog.Info("Saved file", "path", path)
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		slog.Error("Request failed", "url", r.Request.URL, "status", r.StatusCode, "error", err)
	})

	slog.Info("Starting crawl", "url", targetURL)
	if err := c.Visit(targetURL); err != nil {
		return fmt.Errorf("failed to start crawl: %w", err)
	}

	c.Wait()

	slog.Info("Web crawling finished successfully.")
	return nil
}

// isAllowedDomain checks if a given hostname is in the list of allowed domains.
func isAllowedDomain(hostname string, allowedDomains []string) bool {
	for _, domain := range allowedDomains {
		if hostname == domain {
			return true
		}
	}
	return false
}
