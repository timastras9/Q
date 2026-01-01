package recon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TechFingerprinter provides technology fingerprinting for web applications
type TechFingerprinter struct {
	client  *http.Client
	results *FingerprintResult
	mu      sync.Mutex
}

// FingerprintResult contains technology fingerprinting results
type FingerprintResult struct {
	URL           string            `json:"url"`
	Technologies  []Technology      `json:"technologies"`
	Headers       map[string]string `json:"headers"`
	Cookies       []CookieInfo      `json:"cookies,omitempty"`
	SecurityInfo  *SecurityInfo     `json:"security_info,omitempty"`
	ServerInfo    *ServerInfo       `json:"server_info,omitempty"`
	CMSInfo       *CMSInfo          `json:"cms_info,omitempty"`
	FrameworkInfo *FrameworkInfo    `json:"framework_info,omitempty"`
}

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"` // 0-100
	Evidence   []string `json:"evidence,omitempty"`
}

// CookieInfo represents detected cookie information
type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Path     string `json:"path,omitempty"`
}

// SecurityInfo contains security-related findings
type SecurityInfo struct {
	HSTS              bool     `json:"hsts"`
	HSTSMaxAge        int      `json:"hsts_max_age,omitempty"`
	ContentSecurityPolicy bool `json:"csp"`
	XFrameOptions     string   `json:"x_frame_options,omitempty"`
	XContentTypeOptions bool   `json:"x_content_type_options"`
	XSSProtection     string   `json:"xss_protection,omitempty"`
	MissingHeaders    []string `json:"missing_headers,omitempty"`
}

// ServerInfo contains server-related information
type ServerInfo struct {
	Software string `json:"software,omitempty"`
	Version  string `json:"version,omitempty"`
	OS       string `json:"os,omitempty"`
	Language string `json:"language,omitempty"`
}

// CMSInfo contains CMS detection information
type CMSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Plugins []string `json:"plugins,omitempty"`
	Theme   string `json:"theme,omitempty"`
}

// FrameworkInfo contains framework detection information
type FrameworkInfo struct {
	Frontend []string `json:"frontend,omitempty"`
	Backend  []string `json:"backend,omitempty"`
	CSS      []string `json:"css,omitempty"`
}

// TechSignature defines a technology detection signature
type TechSignature struct {
	Name       string
	Category   string
	HeaderMatch map[string]*regexp.Regexp
	CookieMatch []*regexp.Regexp
	HTMLMatch   []*regexp.Regexp
	URLMatch    []*regexp.Regexp
	MetaMatch   map[string]*regexp.Regexp
	ScriptMatch []*regexp.Regexp
}

// NewTechFingerprinter creates a new technology fingerprinter
func NewTechFingerprinter() *TechFingerprinter {
	return &TechFingerprinter{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		results: &FingerprintResult{
			Technologies: []Technology{},
			Headers:      make(map[string]string),
			Cookies:      []CookieInfo{},
		},
	}
}

// Fingerprint performs technology fingerprinting on a URL
func (t *TechFingerprinter) Fingerprint(ctx context.Context, targetURL string) (*FingerprintResult, error) {
	t.results.URL = targetURL

	// Fetch the main page
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		return nil, err
	}
	html := string(body)

	// Analyze headers
	t.analyzeHeaders(resp)

	// Analyze cookies
	t.analyzeCookies(resp)

	// Analyze HTML content
	t.analyzeHTML(html)

	// Check security headers
	t.analyzeSecurityHeaders(resp)

	// Probe for known paths
	t.probeKnownPaths(ctx, targetURL)

	// Deduplicate technologies
	t.deduplicateTechnologies()

	return t.results, nil
}

// analyzeHeaders analyzes HTTP response headers
func (t *TechFingerprinter) analyzeHeaders(resp *http.Response) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, values := range resp.Header {
		if len(values) > 0 {
			t.results.Headers[key] = values[0]
		}
	}

	// Server header
	if server := resp.Header.Get("Server"); server != "" {
		t.results.ServerInfo = &ServerInfo{Software: server}
		t.addTechnology("Server", "Web Server", server, 90, []string{"Server header"})

		// Parse server details
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "nginx") {
			t.addTechnology("nginx", "Web Server", extractVersion(server, `nginx[/\s]*([\d.]+)`), 95, []string{"Server header"})
		}
		if strings.Contains(serverLower, "apache") {
			t.addTechnology("Apache", "Web Server", extractVersion(server, `Apache[/\s]*([\d.]+)`), 95, []string{"Server header"})
		}
		if strings.Contains(serverLower, "iis") {
			t.addTechnology("Microsoft IIS", "Web Server", extractVersion(server, `IIS[/\s]*([\d.]+)`), 95, []string{"Server header"})
		}
		if strings.Contains(serverLower, "cloudflare") {
			t.addTechnology("Cloudflare", "CDN", "", 95, []string{"Server header"})
		}
	}

	// X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		t.addTechnology("X-Powered-By", "Backend", poweredBy, 90, []string{"X-Powered-By header"})

		poweredByLower := strings.ToLower(poweredBy)
		if strings.Contains(poweredByLower, "php") {
			t.addTechnology("PHP", "Programming Language", extractVersion(poweredBy, `PHP[/\s]*([\d.]+)`), 95, []string{"X-Powered-By header"})
		}
		if strings.Contains(poweredByLower, "asp.net") {
			t.addTechnology("ASP.NET", "Framework", extractVersion(poweredBy, `ASP\.NET[/\s]*([\d.]+)`), 95, []string{"X-Powered-By header"})
		}
		if strings.Contains(poweredByLower, "express") {
			t.addTechnology("Express.js", "Framework", "", 90, []string{"X-Powered-By header"})
		}
	}

	// Via header (proxy/CDN)
	if via := resp.Header.Get("Via"); via != "" {
		if strings.Contains(strings.ToLower(via), "varnish") {
			t.addTechnology("Varnish", "Caching", "", 85, []string{"Via header"})
		}
	}

	// X-Generator
	if generator := resp.Header.Get("X-Generator"); generator != "" {
		t.addTechnology(generator, "CMS", "", 85, []string{"X-Generator header"})
	}
}

// analyzeCookies analyzes cookies for technology fingerprinting
func (t *TechFingerprinter) analyzeCookies(resp *http.Response) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		sameSite := ""
		switch cookie.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		t.results.Cookies = append(t.results.Cookies, CookieInfo{
			Name:     cookie.Name,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
			SameSite: sameSite,
			Path:     cookie.Path,
		})

		// Cookie-based detection
		nameLower := strings.ToLower(cookie.Name)

		// PHP
		if nameLower == "phpsessid" {
			t.addTechnology("PHP", "Programming Language", "", 90, []string{"PHPSESSID cookie"})
		}

		// ASP.NET
		if nameLower == "asp.net_sessionid" || nameLower == ".aspxauth" {
			t.addTechnology("ASP.NET", "Framework", "", 90, []string{"ASP.NET session cookie"})
		}

		// Java
		if nameLower == "jsessionid" {
			t.addTechnology("Java", "Programming Language", "", 90, []string{"JSESSIONID cookie"})
		}

		// Django
		if nameLower == "csrftoken" || nameLower == "django_language" {
			t.addTechnology("Django", "Framework", "", 75, []string{"Django cookie pattern"})
		}

		// Rails
		if strings.HasPrefix(nameLower, "_") && strings.HasSuffix(nameLower, "_session") {
			t.addTechnology("Ruby on Rails", "Framework", "", 70, []string{"Rails session cookie pattern"})
		}

		// WordPress
		if strings.HasPrefix(nameLower, "wordpress_") || strings.HasPrefix(nameLower, "wp-") {
			t.addTechnology("WordPress", "CMS", "", 95, []string{"WordPress cookie"})
		}

		// Laravel
		if nameLower == "laravel_session" || nameLower == "xsrf-token" {
			t.addTechnology("Laravel", "Framework", "", 85, []string{"Laravel session cookie"})
		}

		// Express/Connect
		if nameLower == "connect.sid" {
			t.addTechnology("Express.js", "Framework", "", 80, []string{"Express session cookie"})
		}
	}
}

// analyzeHTML analyzes HTML content for technology fingerprinting
func (t *TechFingerprinter) analyzeHTML(html string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	htmlLower := strings.ToLower(html)

	// Meta generator
	generatorRe := regexp.MustCompile(`<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	if matches := generatorRe.FindStringSubmatch(html); len(matches) > 1 {
		gen := matches[1]
		t.addTechnology(gen, "CMS/Generator", extractVersion(gen, `([\d.]+)`), 95, []string{"meta generator"})

		// Specific CMS detection
		genLower := strings.ToLower(gen)
		if strings.Contains(genLower, "wordpress") {
			ver := extractVersion(gen, `WordPress\s*([\d.]+)`)
			t.addTechnology("WordPress", "CMS", ver, 98, []string{"meta generator"})
		}
		if strings.Contains(genLower, "drupal") {
			t.addTechnology("Drupal", "CMS", extractVersion(gen, `Drupal\s*([\d.]+)`), 98, []string{"meta generator"})
		}
		if strings.Contains(genLower, "joomla") {
			t.addTechnology("Joomla", "CMS", extractVersion(gen, `Joomla!\s*([\d.]+)`), 98, []string{"meta generator"})
		}
	}

	// JavaScript frameworks/libraries
	jsPatterns := map[string]struct {
		pattern  string
		category string
	}{
		"React":     {`react[.-]dom|reactdom|__REACT_DEVTOOLS`, "JavaScript Framework"},
		"Vue.js":    {`vue[.-]?([\d.]+)?\.js|__VUE__|v-cloak|v-bind`, "JavaScript Framework"},
		"Angular":   {`angular[.-]?([\d.]+)?\.js|ng-app|ng-controller|ng-version`, "JavaScript Framework"},
		"jQuery":    {`jquery[.-]?([\d.]+)?\.js|jquery\.min\.js`, "JavaScript Library"},
		"Bootstrap": {`bootstrap[.-]?([\d.]+)?\.js|bootstrap\.min\.(js|css)`, "CSS Framework"},
		"Tailwind":  {`tailwind`, "CSS Framework"},
		"Next.js":   {`_next/static|__NEXT_DATA__`, "JavaScript Framework"},
		"Nuxt.js":   {`_nuxt/|__NUXT__`, "JavaScript Framework"},
		"Svelte":    {`svelte`, "JavaScript Framework"},
		"Ember.js":  {`ember[.-]?([\d.]+)?\.js`, "JavaScript Framework"},
		"Backbone":  {`backbone[.-]?([\d.]+)?\.js`, "JavaScript Library"},
		"Lodash":    {`lodash[.-]?([\d.]+)?\.js`, "JavaScript Library"},
		"Moment.js": {`moment[.-]?([\d.]+)?\.js`, "JavaScript Library"},
		"D3.js":     {`d3[.-]?([\d.]+)?\.js`, "JavaScript Library"},
		"Three.js":  {`three[.-]?([\d.]+)?\.js`, "JavaScript Library"},
		"Socket.io": {`socket\.io`, "JavaScript Library"},
	}

	for tech, info := range jsPatterns {
		re := regexp.MustCompile(`(?i)` + info.pattern)
		if re.MatchString(html) {
			version := ""
			if vMatch := regexp.MustCompile(`(?i)` + strings.ReplaceAll(info.pattern, `([\d.]+)?`, `([\d.]+)`) + ``).FindStringSubmatch(html); len(vMatch) > 1 {
				version = vMatch[1]
			}
			t.addTechnology(tech, info.category, version, 80, []string{"HTML/JS content"})
		}
	}

	// WordPress specific
	if strings.Contains(htmlLower, "wp-content") || strings.Contains(htmlLower, "wp-includes") {
		t.addTechnology("WordPress", "CMS", "", 95, []string{"wp-content/wp-includes paths"})
	}

	// Drupal specific
	if strings.Contains(htmlLower, "drupal.js") || strings.Contains(html, "Drupal.settings") {
		t.addTechnology("Drupal", "CMS", "", 90, []string{"Drupal.js or Drupal.settings"})
	}

	// Magento
	if strings.Contains(htmlLower, "mage/") || strings.Contains(htmlLower, "magento") {
		t.addTechnology("Magento", "E-commerce", "", 85, []string{"Magento paths"})
	}

	// Shopify
	if strings.Contains(htmlLower, "cdn.shopify.com") || strings.Contains(htmlLower, "shopify") {
		t.addTechnology("Shopify", "E-commerce", "", 95, []string{"Shopify CDN"})
	}

	// Google Analytics
	if strings.Contains(htmlLower, "google-analytics.com") || strings.Contains(htmlLower, "ga.js") || strings.Contains(htmlLower, "gtag") {
		t.addTechnology("Google Analytics", "Analytics", "", 90, []string{"GA script"})
	}

	// Google Tag Manager
	if strings.Contains(htmlLower, "googletagmanager.com") {
		t.addTechnology("Google Tag Manager", "Tag Manager", "", 95, []string{"GTM script"})
	}

	// Cloudflare
	if strings.Contains(htmlLower, "cloudflare") || strings.Contains(htmlLower, "__cf_bm") {
		t.addTechnology("Cloudflare", "CDN", "", 85, []string{"Cloudflare markers"})
	}

	// Font Awesome
	if strings.Contains(htmlLower, "font-awesome") || strings.Contains(htmlLower, "fontawesome") {
		t.addTechnology("Font Awesome", "Font", "", 90, []string{"Font Awesome CSS"})
	}
}

// analyzeSecurityHeaders checks security-related headers
func (t *TechFingerprinter) analyzeSecurityHeaders(resp *http.Response) {
	t.mu.Lock()
	defer t.mu.Unlock()

	secInfo := &SecurityInfo{
		MissingHeaders: []string{},
	}

	// HSTS
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		secInfo.HSTS = true
		if match := regexp.MustCompile(`max-age=(\d+)`).FindStringSubmatch(hsts); len(match) > 1 {
			fmt.Sscanf(match[1], "%d", &secInfo.HSTSMaxAge)
		}
	} else {
		secInfo.MissingHeaders = append(secInfo.MissingHeaders, "Strict-Transport-Security")
	}

	// CSP
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		secInfo.ContentSecurityPolicy = true
	} else {
		secInfo.MissingHeaders = append(secInfo.MissingHeaders, "Content-Security-Policy")
	}

	// X-Frame-Options
	if xfo := resp.Header.Get("X-Frame-Options"); xfo != "" {
		secInfo.XFrameOptions = xfo
	} else {
		secInfo.MissingHeaders = append(secInfo.MissingHeaders, "X-Frame-Options")
	}

	// X-Content-Type-Options
	if xcto := resp.Header.Get("X-Content-Type-Options"); xcto == "nosniff" {
		secInfo.XContentTypeOptions = true
	} else {
		secInfo.MissingHeaders = append(secInfo.MissingHeaders, "X-Content-Type-Options")
	}

	// X-XSS-Protection
	if xxss := resp.Header.Get("X-XSS-Protection"); xxss != "" {
		secInfo.XSSProtection = xxss
	}

	t.results.SecurityInfo = secInfo
}

// probeKnownPaths probes for known paths to detect technologies
func (t *TechFingerprinter) probeKnownPaths(ctx context.Context, baseURL string) {
	baseURL = strings.TrimSuffix(baseURL, "/")

	paths := []struct {
		path     string
		tech     string
		category string
	}{
		{"/wp-admin/", "WordPress", "CMS"},
		{"/wp-login.php", "WordPress", "CMS"},
		{"/administrator/", "Joomla", "CMS"},
		{"/admin/", "Admin Panel", "CMS"},
		{"/user/login", "Drupal", "CMS"},
		{"/phpmyadmin/", "phpMyAdmin", "Database Admin"},
		{"/adminer.php", "Adminer", "Database Admin"},
		{"/robots.txt", "robots.txt", "Configuration"},
		{"/sitemap.xml", "Sitemap", "SEO"},
		{"/graphql", "GraphQL", "API"},
		{"/api/", "API", "API"},
		{"/swagger/", "Swagger", "API Documentation"},
		{"/api-docs/", "API Docs", "API Documentation"},
		{"/.git/config", "Git", "Version Control"},
		{"/.env", "Environment File", "Configuration"},
		{"/server-status", "Apache mod_status", "Server"},
		{"/nginx_status", "Nginx status", "Server"},
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent requests

	for _, p := range paths {
		wg.Add(1)
		go func(path, tech, category string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			url := baseURL + path
			req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
			if err != nil {
				return
			}

			resp, err := t.client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
				t.mu.Lock()
				t.addTechnologyUnsafe(tech, category, "", 70, []string{fmt.Sprintf("Path exists: %s", path)})
				t.mu.Unlock()
			}
		}(p.path, p.tech, p.category)
	}

	wg.Wait()
}

// addTechnology adds a technology to results (thread-safe)
func (t *TechFingerprinter) addTechnology(name, category, version string, confidence int, evidence []string) {
	t.results.Technologies = append(t.results.Technologies, Technology{
		Name:       name,
		Category:   category,
		Version:    version,
		Confidence: confidence,
		Evidence:   evidence,
	})
}

// addTechnologyUnsafe adds a technology without locking (caller must hold lock)
func (t *TechFingerprinter) addTechnologyUnsafe(name, category, version string, confidence int, evidence []string) {
	t.results.Technologies = append(t.results.Technologies, Technology{
		Name:       name,
		Category:   category,
		Version:    version,
		Confidence: confidence,
		Evidence:   evidence,
	})
}

// deduplicateTechnologies removes duplicate technologies, keeping highest confidence
func (t *TechFingerprinter) deduplicateTechnologies() {
	t.mu.Lock()
	defer t.mu.Unlock()

	seen := make(map[string]int) // name -> index in unique slice
	unique := []Technology{}

	for _, tech := range t.results.Technologies {
		key := strings.ToLower(tech.Name)
		if idx, exists := seen[key]; exists {
			// Update if higher confidence or has version
			if tech.Confidence > unique[idx].Confidence || (tech.Version != "" && unique[idx].Version == "") {
				unique[idx].Confidence = tech.Confidence
				if tech.Version != "" {
					unique[idx].Version = tech.Version
				}
				unique[idx].Evidence = append(unique[idx].Evidence, tech.Evidence...)
			}
		} else {
			seen[key] = len(unique)
			unique = append(unique, tech)
		}
	}

	t.results.Technologies = unique
}

// extractVersion extracts version from a string using regex
func extractVersion(s string, pattern string) string {
	re := regexp.MustCompile(`(?i)` + pattern)
	if matches := re.FindStringSubmatch(s); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// GenerateReport creates a human-readable report
func (t *TechFingerprinter) GenerateReport() string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                 TECHNOLOGY FINGERPRINT                       ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Target: %s\n\n", t.results.URL))

	// Group technologies by category
	categories := make(map[string][]Technology)
	for _, tech := range t.results.Technologies {
		categories[tech.Category] = append(categories[tech.Category], tech)
	}

	if len(t.results.Technologies) > 0 {
		sb.WriteString("🔍 DETECTED TECHNOLOGIES:\n")
		for category, techs := range categories {
			sb.WriteString(fmt.Sprintf("\n  [%s]\n", category))
			for _, tech := range techs {
				version := ""
				if tech.Version != "" {
					version = fmt.Sprintf(" v%s", tech.Version)
				}
				sb.WriteString(fmt.Sprintf("    • %s%s (confidence: %d%%)\n", tech.Name, version, tech.Confidence))
			}
		}
		sb.WriteString("\n")
	}

	// Server info
	if t.results.ServerInfo != nil && t.results.ServerInfo.Software != "" {
		sb.WriteString("🖥️  SERVER:\n")
		sb.WriteString(fmt.Sprintf("    %s\n\n", t.results.ServerInfo.Software))
	}

	// Security headers
	if t.results.SecurityInfo != nil {
		sb.WriteString("🔒 SECURITY HEADERS:\n")
		sb.WriteString(fmt.Sprintf("    HSTS: %v\n", t.results.SecurityInfo.HSTS))
		sb.WriteString(fmt.Sprintf("    CSP: %v\n", t.results.SecurityInfo.ContentSecurityPolicy))
		sb.WriteString(fmt.Sprintf("    X-Frame-Options: %s\n", t.results.SecurityInfo.XFrameOptions))
		sb.WriteString(fmt.Sprintf("    X-Content-Type-Options: %v\n", t.results.SecurityInfo.XContentTypeOptions))

		if len(t.results.SecurityInfo.MissingHeaders) > 0 {
			sb.WriteString("\n  ⚠️  MISSING SECURITY HEADERS:\n")
			for _, h := range t.results.SecurityInfo.MissingHeaders {
				sb.WriteString(fmt.Sprintf("    • %s\n", h))
			}
		}
		sb.WriteString("\n")
	}

	// Cookies
	if len(t.results.Cookies) > 0 {
		sb.WriteString("🍪 COOKIES:\n")
		for _, cookie := range t.results.Cookies {
			flags := []string{}
			if cookie.Secure {
				flags = append(flags, "Secure")
			}
			if cookie.HTTPOnly {
				flags = append(flags, "HttpOnly")
			}
			if cookie.SameSite != "" {
				flags = append(flags, "SameSite="+cookie.SameSite)
			}
			flagStr := ""
			if len(flags) > 0 {
				flagStr = " [" + strings.Join(flags, ", ") + "]"
			}
			sb.WriteString(fmt.Sprintf("    • %s%s\n", cookie.Name, flagStr))
		}
	}

	return sb.String()
}

// ToJSON returns the results as JSON
func (t *TechFingerprinter) ToJSON() (string, error) {
	data, err := json.MarshalIndent(t.results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
