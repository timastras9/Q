package webapp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type WebScanner struct {
	client      *http.Client
	timeout     time.Duration
	concurrency int
	userAgent   string
}

type WebScanResult struct {
	URL         string
	StartTime   time.Time
	EndTime     time.Time
	Findings    []Finding
	Headers     map[string]string
	Technologies []string
	Forms       []Form
	Links       []string
	Cookies     []Cookie
}

type Finding struct {
	Type        string // sqli, xss, lfi, rce, etc
	Severity    string // info, low, medium, high, critical
	URL         string
	Parameter   string
	Payload     string
	Evidence    string
	Description string
	Remediation string
}

type Form struct {
	Action  string
	Method  string
	Inputs  []FormInput
}

type FormInput struct {
	Name  string
	Type  string
	Value string
}

type Cookie struct {
	Name     string
	Value    string
	Secure   bool
	HttpOnly bool
	SameSite string
}

func NewWebScanner() *WebScanner {
	return &WebScanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		timeout:     30 * time.Second,
		concurrency: 10,
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

func (w *WebScanner) Scan(ctx context.Context, targetURL string) (*WebScanResult, error) {
	result := &WebScanResult{
		URL:       targetURL,
		StartTime: time.Now(),
		Headers:   make(map[string]string),
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Initial request
	resp, body, err := w.fetch(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}

	// Collect headers
	for k, v := range resp.Header {
		result.Headers[k] = strings.Join(v, ", ")
	}

	// Collect cookies
	for _, cookie := range resp.Cookies() {
		result.Cookies = append(result.Cookies, Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSiteString(cookie.SameSite),
		})
	}

	// Run all checks
	var wg sync.WaitGroup
	var mu sync.Mutex

	addFinding := func(f Finding) {
		mu.Lock()
		result.Findings = append(result.Findings, f)
		mu.Unlock()
	}

	// Header security checks
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, f := range w.checkSecurityHeaders(resp.Header) {
			f.URL = targetURL
			addFinding(f)
		}
	}()

	// Cookie security checks
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, f := range w.checkCookieSecurity(resp.Cookies()) {
			f.URL = targetURL
			addFinding(f)
		}
	}()

	// Technology detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		techs := w.detectTechnologies(resp.Header, body)
		mu.Lock()
		result.Technologies = techs
		mu.Unlock()
	}()

	// Extract forms and links
	wg.Add(1)
	go func() {
		defer wg.Done()
		forms := w.extractForms(body, parsedURL)
		links := w.extractLinks(body, parsedURL)
		mu.Lock()
		result.Forms = forms
		result.Links = links
		mu.Unlock()
	}()

	wg.Wait()

	// Test extracted forms for vulnerabilities
	for _, form := range result.Forms {
		findings := w.testForm(ctx, form, parsedURL)
		for _, f := range findings {
			addFinding(f)
		}
	}

	// Test URL parameters
	if parsedURL.RawQuery != "" {
		findings := w.testParameters(ctx, targetURL)
		for _, f := range findings {
			addFinding(f)
		}
	}

	result.EndTime = time.Now()
	return result, nil
}

func (w *WebScanner) fetch(ctx context.Context, targetURL string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", w.userAgent)

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}

	return resp, string(body), nil
}

func (w *WebScanner) checkSecurityHeaders(headers http.Header) []Finding {
	var findings []Finding

	securityHeaders := map[string]struct {
		missing     string
		description string
		severity    string
	}{
		"X-Frame-Options": {
			missing:     "X-Frame-Options header missing",
			description: "The site can be embedded in iframes, enabling clickjacking attacks",
			severity:    "medium",
		},
		"X-Content-Type-Options": {
			missing:     "X-Content-Type-Options header missing",
			description: "Browser may MIME-sniff content, enabling XSS attacks",
			severity:    "low",
		},
		"Strict-Transport-Security": {
			missing:     "HSTS header missing",
			description: "Site doesn't enforce HTTPS, vulnerable to protocol downgrade",
			severity:    "medium",
		},
		"Content-Security-Policy": {
			missing:     "Content-Security-Policy header missing",
			description: "No CSP policy, increased XSS risk",
			severity:    "medium",
		},
		"X-XSS-Protection": {
			missing:     "X-XSS-Protection header missing",
			description: "Browser XSS filter not enabled",
			severity:    "low",
		},
	}

	for header, info := range securityHeaders {
		if headers.Get(header) == "" {
			findings = append(findings, Finding{
				Type:        "security_header",
				Severity:    info.severity,
				Description: info.missing,
				Evidence:    info.description,
				Remediation: fmt.Sprintf("Add %s header to HTTP responses", header),
			})
		}
	}

	// Check for information disclosure headers
	infoHeaders := []string{"Server", "X-Powered-By", "X-AspNet-Version"}
	for _, header := range infoHeaders {
		if val := headers.Get(header); val != "" {
			findings = append(findings, Finding{
				Type:        "info_disclosure",
				Severity:    "info",
				Description: fmt.Sprintf("Server information disclosed: %s", header),
				Evidence:    val,
				Remediation: fmt.Sprintf("Remove or hide the %s header", header),
			})
		}
	}

	return findings
}

func (w *WebScanner) checkCookieSecurity(cookies []*http.Cookie) []Finding {
	var findings []Finding

	for _, cookie := range cookies {
		if !cookie.Secure {
			findings = append(findings, Finding{
				Type:        "insecure_cookie",
				Severity:    "medium",
				Parameter:   cookie.Name,
				Description: "Cookie missing Secure flag",
				Evidence:    fmt.Sprintf("Cookie '%s' can be sent over HTTP", cookie.Name),
				Remediation: "Set the Secure flag on all cookies",
			})
		}

		if !cookie.HttpOnly {
			findings = append(findings, Finding{
				Type:        "insecure_cookie",
				Severity:    "medium",
				Parameter:   cookie.Name,
				Description: "Cookie missing HttpOnly flag",
				Evidence:    fmt.Sprintf("Cookie '%s' accessible via JavaScript", cookie.Name),
				Remediation: "Set the HttpOnly flag on session cookies",
			})
		}

		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
			findings = append(findings, Finding{
				Type:        "insecure_cookie",
				Severity:    "low",
				Parameter:   cookie.Name,
				Description: "Cookie SameSite not set to Strict/Lax",
				Evidence:    fmt.Sprintf("Cookie '%s' may be sent with cross-site requests", cookie.Name),
				Remediation: "Set SameSite=Strict or SameSite=Lax",
			})
		}
	}

	return findings
}

func (w *WebScanner) detectTechnologies(headers http.Header, body string) []string {
	var techs []string

	// Server header
	if server := headers.Get("Server"); server != "" {
		techs = append(techs, server)
	}

	// X-Powered-By
	if powered := headers.Get("X-Powered-By"); powered != "" {
		techs = append(techs, powered)
	}

	// Body patterns
	patterns := map[string]string{
		"WordPress":    `wp-content|wp-includes|WordPress`,
		"Drupal":       `Drupal|drupal\.js`,
		"Joomla":       `Joomla|/media/jui/`,
		"Laravel":      `laravel_session|Laravel`,
		"Django":       `csrfmiddlewaretoken|django`,
		"Rails":        `csrf-token.*authenticity_token|Rails`,
		"React":        `react\.production\.min\.js|__REACT`,
		"Vue.js":       `vue\.js|Vue\.js`,
		"Angular":      `ng-app|angular\.js`,
		"jQuery":       `jquery.*\.js`,
		"Bootstrap":    `bootstrap\.min\.(css|js)`,
		"ASP.NET":      `__VIEWSTATE|__EVENTVALIDATION`,
		"PHP":          `\.php["\?]|PHPSESSID`,
		"Nginx":        `nginx`,
		"Apache":       `Apache`,
		"IIS":          `Microsoft-IIS`,
	}

	bodyLower := strings.ToLower(body)
	for tech, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(bodyLower) || re.MatchString(headers.Get("Server")) {
			if !contains(techs, tech) {
				techs = append(techs, tech)
			}
		}
	}

	return techs
}

func (w *WebScanner) extractForms(body string, baseURL *url.URL) []Form {
	var forms []Form

	formRe := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	actionRe := regexp.MustCompile(`(?i)action=["']([^"']*)["']`)
	methodRe := regexp.MustCompile(`(?i)method=["']([^"']*)["']`)
	inputRe := regexp.MustCompile(`(?i)<input[^>]*>`)
	nameRe := regexp.MustCompile(`(?i)name=["']([^"']*)["']`)
	typeRe := regexp.MustCompile(`(?i)type=["']([^"']*)["']`)
	valueRe := regexp.MustCompile(`(?i)value=["']([^"']*)["']`)

	formMatches := formRe.FindAllStringSubmatch(body, -1)
	for _, match := range formMatches {
		formHTML := match[0]
		formContent := match[1]

		form := Form{Method: "GET"}

		if actionMatch := actionRe.FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = resolveURL(baseURL, actionMatch[1])
		} else {
			form.Action = baseURL.String()
		}

		if methodMatch := methodRe.FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		inputMatches := inputRe.FindAllString(formContent, -1)
		for _, inputHTML := range inputMatches {
			input := FormInput{Type: "text"}

			if nameMatch := nameRe.FindStringSubmatch(inputHTML); len(nameMatch) > 1 {
				input.Name = nameMatch[1]
			}
			if typeMatch := typeRe.FindStringSubmatch(inputHTML); len(typeMatch) > 1 {
				input.Type = typeMatch[1]
			}
			if valueMatch := valueRe.FindStringSubmatch(inputHTML); len(valueMatch) > 1 {
				input.Value = valueMatch[1]
			}

			if input.Name != "" {
				form.Inputs = append(form.Inputs, input)
			}
		}

		forms = append(forms, form)
	}

	return forms
}

func (w *WebScanner) extractLinks(body string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	linkRe := regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)
	matches := linkRe.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := resolveURL(baseURL, match[1])
			if !seen[link] && strings.HasPrefix(link, baseURL.Scheme+"://"+baseURL.Host) {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	return links
}

func (w *WebScanner) testForm(ctx context.Context, form Form, baseURL *url.URL) []Finding {
	var findings []Finding

	// SQL Injection payloads
	sqliPayloads := []string{
		"'",
		"\"",
		"' OR '1'='1",
		"1' OR '1'='1' --",
		"1; DROP TABLE users--",
		"' UNION SELECT NULL--",
	}

	// XSS payloads
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"'\"><script>alert(1)</script>",
		"<svg onload=alert(1)>",
	}

	// LFI payloads
	lfiPayloads := []string{
		"../../../etc/passwd",
		"....//....//....//etc/passwd",
		"/etc/passwd",
		"..\\..\\..\\windows\\win.ini",
	}

	for _, input := range form.Inputs {
		if input.Type == "hidden" || input.Type == "submit" {
			continue
		}

		// Test SQLi
		for _, payload := range sqliPayloads {
			if finding := w.testPayload(ctx, form, input.Name, payload, "sqli"); finding != nil {
				findings = append(findings, *finding)
				break // One finding per parameter
			}
		}

		// Test XSS
		for _, payload := range xssPayloads {
			if finding := w.testPayload(ctx, form, input.Name, payload, "xss"); finding != nil {
				findings = append(findings, *finding)
				break
			}
		}

		// Test LFI on file-like parameters
		if strings.Contains(strings.ToLower(input.Name), "file") ||
			strings.Contains(strings.ToLower(input.Name), "path") ||
			strings.Contains(strings.ToLower(input.Name), "page") {
			for _, payload := range lfiPayloads {
				if finding := w.testPayload(ctx, form, input.Name, payload, "lfi"); finding != nil {
					findings = append(findings, *finding)
					break
				}
			}
		}
	}

	return findings
}

func (w *WebScanner) testPayload(ctx context.Context, form Form, param, payload, vulnType string) *Finding {
	values := url.Values{}
	for _, input := range form.Inputs {
		if input.Name == param {
			values.Set(input.Name, payload)
		} else {
			values.Set(input.Name, input.Value)
		}
	}

	var resp *http.Response
	var body string
	var err error

	if form.Method == "POST" {
		req, _ := http.NewRequestWithContext(ctx, "POST", form.Action, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", w.userAgent)
		resp, err = w.client.Do(req)
	} else {
		u, _ := url.Parse(form.Action)
		u.RawQuery = values.Encode()
		req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		req.Header.Set("User-Agent", w.userAgent)
		resp, err = w.client.Do(req)
	}

	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body = string(bodyBytes)

	// Check for vulnerability indicators
	switch vulnType {
	case "sqli":
		errorPatterns := []string{
			"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
			"SQLite", "ODBC", "Microsoft SQL", "syntax error",
			"Unclosed quotation mark", "quoted string not properly terminated",
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(body, pattern) {
				return &Finding{
					Type:        "sqli",
					Severity:    "critical",
					URL:         form.Action,
					Parameter:   param,
					Payload:     payload,
					Evidence:    pattern,
					Description: "SQL Injection vulnerability detected",
					Remediation: "Use parameterized queries/prepared statements",
				}
			}
		}

	case "xss":
		if strings.Contains(body, payload) {
			return &Finding{
				Type:        "xss",
				Severity:    "high",
				URL:         form.Action,
				Parameter:   param,
				Payload:     payload,
				Evidence:    "Payload reflected in response",
				Description: "Cross-Site Scripting (XSS) vulnerability detected",
				Remediation: "Encode output and implement CSP",
			}
		}

	case "lfi":
		lfiIndicators := []string{
			"root:x:0:0:", "root:*:0:0:", "[extensions]",
			"[boot loader]", "for 16-bit app support",
		}
		for _, indicator := range lfiIndicators {
			if strings.Contains(body, indicator) {
				return &Finding{
					Type:        "lfi",
					Severity:    "critical",
					URL:         form.Action,
					Parameter:   param,
					Payload:     payload,
					Evidence:    indicator,
					Description: "Local File Inclusion vulnerability detected",
					Remediation: "Validate and sanitize file paths, use allowlist",
				}
			}
		}
	}

	return nil
}

func (w *WebScanner) testParameters(ctx context.Context, targetURL string) []Finding {
	var findings []Finding

	parsedURL, _ := url.Parse(targetURL)
	params := parsedURL.Query()

	for param := range params {
		// Test each parameter
		testPayloads := map[string][]string{
			"sqli": {"'", "\"", "' OR '1'='1"},
			"xss":  {"<script>alert(1)</script>", "'\"><img src=x>"},
		}

		for vulnType, payloads := range testPayloads {
			for _, payload := range payloads {
				testParams := url.Values{}
				for k, v := range params {
					if k == param {
						testParams.Set(k, payload)
					} else {
						testParams.Set(k, v[0])
					}
				}

				testURL := *parsedURL
				testURL.RawQuery = testParams.Encode()

				req, _ := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
				req.Header.Set("User-Agent", w.userAgent)

				resp, err := w.client.Do(req)
				if err != nil {
					continue
				}

				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if vulnType == "sqli" {
					errorPatterns := []string{"SQL syntax", "mysql_fetch", "ORA-"}
					for _, pattern := range errorPatterns {
						if strings.Contains(string(body), pattern) {
							findings = append(findings, Finding{
								Type:        "sqli",
								Severity:    "critical",
								URL:         targetURL,
								Parameter:   param,
								Payload:     payload,
								Evidence:    pattern,
								Description: "SQL Injection in URL parameter",
								Remediation: "Use parameterized queries",
							})
							break
						}
					}
				}

				if vulnType == "xss" && strings.Contains(string(body), payload) {
					findings = append(findings, Finding{
						Type:        "xss",
						Severity:    "high",
						URL:         targetURL,
						Parameter:   param,
						Payload:     payload,
						Description: "Reflected XSS in URL parameter",
						Remediation: "Encode output",
					})
				}
			}
		}
	}

	return findings
}

// FormatResult returns a human-readable report
func (r *WebScanResult) FormatResult() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Web Scan Results for %s\n", r.URL))
	sb.WriteString(fmt.Sprintf("Duration: %v\n\n", r.EndTime.Sub(r.StartTime)))

	if len(r.Technologies) > 0 {
		sb.WriteString("Technologies Detected:\n")
		for _, tech := range r.Technologies {
			sb.WriteString(fmt.Sprintf("  - %s\n", tech))
		}
		sb.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		sb.WriteString(fmt.Sprintf("Findings (%d):\n", len(r.Findings)))
		for _, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(f.Severity), f.Type))
			if f.Parameter != "" {
				sb.WriteString(fmt.Sprintf("    Parameter: %s\n", f.Parameter))
			}
			if f.Payload != "" {
				sb.WriteString(fmt.Sprintf("    Payload: %s\n", f.Payload))
			}
			sb.WriteString(fmt.Sprintf("    Description: %s\n", f.Description))
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("    Remediation: %s\n", f.Remediation))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("No vulnerabilities found.\n")
	}

	return sb.String()
}

func resolveURL(base *url.URL, ref string) string {
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(refURL).String()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}
