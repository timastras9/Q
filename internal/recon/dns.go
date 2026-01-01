package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSScanner provides DNS enumeration and subdomain discovery
type DNSScanner struct {
	client     *http.Client
	resolver   *net.Resolver
	results    *DNSScanResult
	mu         sync.Mutex
	maxWorkers int
}

// DNSScanResult contains DNS enumeration results
type DNSScanResult struct {
	Domain        string             `json:"domain"`
	Subdomains    []SubdomainResult  `json:"subdomains"`
	DNSRecords    map[string][]string `json:"dns_records"`
	CTLogEntries  []CTLogEntry       `json:"ct_log_entries,omitempty"`
	WildcardDNS   bool               `json:"wildcard_dns"`
	Nameservers   []string           `json:"nameservers,omitempty"`
	ZoneTransfer  bool               `json:"zone_transfer_possible"`
	TotalFound    int                `json:"total_found"`
}

// SubdomainResult represents a discovered subdomain
type SubdomainResult struct {
	Subdomain   string   `json:"subdomain"`
	IPs         []string `json:"ips,omitempty"`
	CNAMEs      []string `json:"cnames,omitempty"`
	Source      string   `json:"source"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	HTTPSStatus int      `json:"https_status,omitempty"`
	Title       string   `json:"title,omitempty"`
}

// CTLogEntry represents a certificate transparency log entry
type CTLogEntry struct {
	Name       string `json:"name"`
	Issuer     string `json:"issuer,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
}

// Common subdomain wordlist
var commonSubdomains = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
	"portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
	"ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum",
	"owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
	"exchange", "app", "gov", "2tty", "vps", "govyty", "hgfgdf",
	"news", "1mail", "testsite", "dav", "files", "mobile",
	"staging", "stage", "beta", "demo", "qa", "uat", "prod",
	"production", "internal", "intranet", "extranet", "private",
	"public", "static", "assets", "img", "images", "media",
	"video", "audio", "download", "downloads", "upload", "uploads",
	"backup", "backups", "db", "database", "mysql", "postgres",
	"redis", "mongo", "mongodb", "elastic", "elasticsearch",
	"kibana", "grafana", "jenkins", "gitlab", "github", "bitbucket",
	"jira", "confluence", "wiki", "docs", "documentation", "help",
	"status", "monitor", "monitoring", "metrics", "logs", "logging",
	"auth", "login", "sso", "oauth", "identity", "accounts",
	"payment", "payments", "billing", "checkout", "cart", "order",
	"orders", "crm", "erp", "hr", "finance", "sales", "marketing",
	"analytics", "report", "reports", "dashboard", "panel",
	"gateway", "proxy", "lb", "loadbalancer", "haproxy", "nginx",
	"apache", "iis", "tomcat", "node", "python", "php", "java",
	"go", "rust", "docker", "kubernetes", "k8s", "rancher",
	"aws", "azure", "gcp", "google", "amazon", "microsoft",
	"office", "o365", "sharepoint", "teams", "outlook", "onedrive",
	"autodiscover", "lyncdiscover", "sip", "meet", "webex", "zoom",
}

// NewDNSScanner creates a new DNS scanner
func NewDNSScanner() *DNSScanner {
	return &DNSScanner{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, network, address)
			},
		},
		results: &DNSScanResult{
			Subdomains: []SubdomainResult{},
			DNSRecords: make(map[string][]string),
		},
		maxWorkers: 50,
	}
}

// ScanDomain performs comprehensive DNS enumeration
func (s *DNSScanner) ScanDomain(ctx context.Context, domain string) (*DNSScanResult, error) {
	s.results.Domain = domain

	// Get base DNS records
	s.getDNSRecords(ctx, domain)

	// Check for wildcard DNS
	s.checkWildcard(ctx, domain)

	// Try zone transfer
	s.tryZoneTransfer(ctx, domain)

	// Subdomain enumeration from multiple sources
	var wg sync.WaitGroup

	// Certificate Transparency logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.searchCTLogs(ctx, domain)
	}()

	// Brute force common subdomains
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.bruteForceSubdomains(ctx, domain)
	}()

	wg.Wait()

	// Resolve and probe all discovered subdomains
	s.resolveSubdomains(ctx)

	// Deduplicate and sort
	s.deduplicateResults()

	s.results.TotalFound = len(s.results.Subdomains)

	return s.results, nil
}

// getDNSRecords gets all DNS records for a domain
func (s *DNSScanner) getDNSRecords(ctx context.Context, domain string) {
	recordTypes := []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"}

	for _, rt := range recordTypes {
		var records []string

		switch rt {
		case "A":
			ips, err := s.resolver.LookupIP(ctx, "ip4", domain)
			if err == nil {
				for _, ip := range ips {
					records = append(records, ip.String())
				}
			}
		case "AAAA":
			ips, err := s.resolver.LookupIP(ctx, "ip6", domain)
			if err == nil {
				for _, ip := range ips {
					records = append(records, ip.String())
				}
			}
		case "MX":
			mxs, err := s.resolver.LookupMX(ctx, domain)
			if err == nil {
				for _, mx := range mxs {
					records = append(records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
				}
			}
		case "TXT":
			txts, err := s.resolver.LookupTXT(ctx, domain)
			if err == nil {
				records = txts
			}
		case "NS":
			nss, err := s.resolver.LookupNS(ctx, domain)
			if err == nil {
				for _, ns := range nss {
					records = append(records, ns.Host)
					s.results.Nameservers = append(s.results.Nameservers, ns.Host)
				}
			}
		case "CNAME":
			cname, err := s.resolver.LookupCNAME(ctx, domain)
			if err == nil && cname != "" {
				records = append(records, cname)
			}
		}

		if len(records) > 0 {
			s.mu.Lock()
			s.results.DNSRecords[rt] = records
			s.mu.Unlock()
		}
	}
}

// checkWildcard checks if domain uses wildcard DNS
func (s *DNSScanner) checkWildcard(ctx context.Context, domain string) {
	randomSub := fmt.Sprintf("randomnonexistent%d.%s", time.Now().UnixNano(), domain)
	ips, err := s.resolver.LookupIP(ctx, "ip4", randomSub)
	if err == nil && len(ips) > 0 {
		s.results.WildcardDNS = true
	}
}

// tryZoneTransfer attempts DNS zone transfer
func (s *DNSScanner) tryZoneTransfer(ctx context.Context, domain string) {
	// Get nameservers
	nss, err := s.resolver.LookupNS(ctx, domain)
	if err != nil {
		return
	}

	for _, ns := range nss {
		// Try zone transfer (AXFR) - simplified check
		conn, err := net.DialTimeout("tcp", ns.Host+":53", 5*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		// Note: Full AXFR implementation would require DNS library
		// For now, just check if port 53/tcp is open
	}
}

// searchCTLogs searches Certificate Transparency logs
func (s *DNSScanner) searchCTLogs(ctx context.Context, domain string) {
	// Use crt.sh API
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return
	}

	var entries []struct {
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotBefore  string `json:"not_before"`
		NotAfter   string `json:"not_after"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		return
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		// Parse name_value which may contain multiple names
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")

			if !strings.HasSuffix(name, domain) {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true

			s.mu.Lock()
			s.results.CTLogEntries = append(s.results.CTLogEntries, CTLogEntry{
				Name:      name,
				Issuer:    entry.IssuerName,
				NotBefore: entry.NotBefore,
				NotAfter:  entry.NotAfter,
			})

			s.results.Subdomains = append(s.results.Subdomains, SubdomainResult{
				Subdomain: name,
				Source:    "ct_logs",
			})
			s.mu.Unlock()
		}
	}
}

// bruteForceSubdomains performs subdomain brute forcing
func (s *DNSScanner) bruteForceSubdomains(ctx context.Context, domain string) {
	jobs := make(chan string, len(commonSubdomains))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				fqdn := sub + "." + domain
				ips, err := s.resolver.LookupIP(ctx, "ip4", fqdn)
				if err == nil && len(ips) > 0 {
					// Skip if wildcard and same IP
					if s.results.WildcardDNS {
						continue
					}

					ipStrs := make([]string, len(ips))
					for i, ip := range ips {
						ipStrs[i] = ip.String()
					}

					s.mu.Lock()
					s.results.Subdomains = append(s.results.Subdomains, SubdomainResult{
						Subdomain: fqdn,
						IPs:       ipStrs,
						Source:    "bruteforce",
					})
					s.mu.Unlock()
				}
			}
		}()
	}

	// Send jobs
	for _, sub := range commonSubdomains {
		jobs <- sub
	}
	close(jobs)

	wg.Wait()
}

// resolveSubdomains resolves and probes discovered subdomains
func (s *DNSScanner) resolveSubdomains(ctx context.Context) {
	jobs := make(chan int, len(s.results.Subdomains))
	var wg sync.WaitGroup

	for i := 0; i < s.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				s.mu.Lock()
				sub := &s.results.Subdomains[idx]
				s.mu.Unlock()

				// Resolve IPs if not already done
				if len(sub.IPs) == 0 {
					ips, err := s.resolver.LookupIP(ctx, "ip4", sub.Subdomain)
					if err == nil {
						for _, ip := range ips {
							sub.IPs = append(sub.IPs, ip.String())
						}
					}
				}

				// Check CNAME
				cname, err := s.resolver.LookupCNAME(ctx, sub.Subdomain)
				if err == nil && cname != "" && cname != sub.Subdomain+"." {
					sub.CNAMEs = append(sub.CNAMEs, cname)
				}

				// Quick HTTP probe
				s.probeHTTP(ctx, sub)
			}
		}()
	}

	for i := range s.results.Subdomains {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
}

// probeHTTP checks HTTP/HTTPS status
func (s *DNSScanner) probeHTTP(ctx context.Context, sub *SubdomainResult) {
	// HTTP
	resp, err := s.client.Get("http://" + sub.Subdomain)
	if err == nil {
		sub.HTTPStatus = resp.StatusCode
		resp.Body.Close()
	}

	// HTTPS
	resp, err = s.client.Get("https://" + sub.Subdomain)
	if err == nil {
		sub.HTTPSStatus = resp.StatusCode
		resp.Body.Close()
	}
}

// deduplicateResults removes duplicate subdomains
func (s *DNSScanner) deduplicateResults() {
	seen := make(map[string]bool)
	unique := []SubdomainResult{}

	for _, sub := range s.results.Subdomains {
		if !seen[sub.Subdomain] {
			seen[sub.Subdomain] = true
			unique = append(unique, sub)
		}
	}

	// Sort by subdomain name
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Subdomain < unique[j].Subdomain
	})

	s.results.Subdomains = unique
}

// GenerateReport creates a human-readable report
func (s *DNSScanner) GenerateReport() string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                 DNS ENUMERATION RESULTS                      ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Domain: %s\n", s.results.Domain))
	sb.WriteString(fmt.Sprintf("Subdomains Found: %d\n", s.results.TotalFound))
	sb.WriteString(fmt.Sprintf("Wildcard DNS: %v\n", s.results.WildcardDNS))
	sb.WriteString(fmt.Sprintf("Zone Transfer: %v\n\n", s.results.ZoneTransfer))

	if len(s.results.DNSRecords) > 0 {
		sb.WriteString("📋 DNS RECORDS:\n")
		for rt, records := range s.results.DNSRecords {
			sb.WriteString(fmt.Sprintf("  %s:\n", rt))
			for _, r := range records {
				sb.WriteString(fmt.Sprintf("    • %s\n", r))
			}
		}
		sb.WriteString("\n")
	}

	if len(s.results.Nameservers) > 0 {
		sb.WriteString("🌐 NAMESERVERS:\n")
		for _, ns := range s.results.Nameservers {
			sb.WriteString(fmt.Sprintf("  • %s\n", ns))
		}
		sb.WriteString("\n")
	}

	if len(s.results.Subdomains) > 0 {
		sb.WriteString("🔍 SUBDOMAINS:\n")
		for _, sub := range s.results.Subdomains {
			status := ""
			if sub.HTTPStatus > 0 {
				status = fmt.Sprintf(" [HTTP:%d]", sub.HTTPStatus)
			}
			if sub.HTTPSStatus > 0 {
				status += fmt.Sprintf(" [HTTPS:%d]", sub.HTTPSStatus)
			}
			ips := ""
			if len(sub.IPs) > 0 {
				ips = fmt.Sprintf(" -> %s", strings.Join(sub.IPs, ", "))
			}
			sb.WriteString(fmt.Sprintf("  • %s%s%s [%s]\n", sub.Subdomain, ips, status, sub.Source))
		}
		sb.WriteString("\n")
	}

	if len(s.results.CTLogEntries) > 0 {
		sb.WriteString(fmt.Sprintf("📜 CT LOG ENTRIES: %d unique certificates\n", len(s.results.CTLogEntries)))
	}

	return sb.String()
}
