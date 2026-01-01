package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ASNScanner provides ASN and WHOIS lookups for scope expansion
type ASNScanner struct {
	client  *http.Client
	results *ASNScanResult
	mu      sync.Mutex
}

// ASNScanResult contains ASN/WHOIS enumeration results
type ASNScanResult struct {
	Target       string          `json:"target"`
	ASNInfo      *ASNInfo        `json:"asn_info,omitempty"`
	WHOISInfo    *WHOISInfo      `json:"whois_info,omitempty"`
	RelatedCIDRs []string        `json:"related_cidrs,omitempty"`
	RelatedIPs   []string        `json:"related_ips,omitempty"`
	OrgDomains   []string        `json:"org_domains,omitempty"`
	PeerASNs     []PeerASN       `json:"peer_asns,omitempty"`
	BGPPrefixes  []BGPPrefix     `json:"bgp_prefixes,omitempty"`
}

// ASNInfo contains Autonomous System Number information
type ASNInfo struct {
	ASN         string   `json:"asn"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Country     string   `json:"country"`
	Registry    string   `json:"registry"`
	AllocDate   string   `json:"allocated_date,omitempty"`
	IPCount     int      `json:"ip_count,omitempty"`
	Prefixes    []string `json:"prefixes,omitempty"`
}

// WHOISInfo contains WHOIS record information
type WHOISInfo struct {
	Domain       string   `json:"domain,omitempty"`
	Registrar    string   `json:"registrar,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Country      string   `json:"country,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Expires      string   `json:"expires,omitempty"`
	Nameservers  []string `json:"nameservers,omitempty"`
	Status       []string `json:"status,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	RawData      string   `json:"raw_data,omitempty"`
}

// PeerASN represents a peer ASN
type PeerASN struct {
	ASN  string `json:"asn"`
	Name string `json:"name"`
}

// BGPPrefix represents a BGP prefix
type BGPPrefix struct {
	Prefix  string `json:"prefix"`
	Name    string `json:"name"`
	Country string `json:"country,omitempty"`
}

// NewASNScanner creates a new ASN scanner
func NewASNScanner() *ASNScanner {
	return &ASNScanner{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		results: &ASNScanResult{
			RelatedCIDRs: []string{},
			RelatedIPs:   []string{},
			OrgDomains:   []string{},
			PeerASNs:     []PeerASN{},
			BGPPrefixes:  []BGPPrefix{},
		},
	}
}

// ScanTarget performs ASN/WHOIS lookup on a target (IP or domain)
func (s *ASNScanner) ScanTarget(ctx context.Context, target string) (*ASNScanResult, error) {
	s.results.Target = target

	// Determine if target is IP or domain
	ip := net.ParseIP(target)
	if ip != nil {
		// Target is an IP address
		s.lookupIPASN(ctx, target)
	} else {
		// Target is a domain - resolve to IP first
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
		if err == nil && len(ips) > 0 {
			s.lookupIPASN(ctx, ips[0].String())
		}
		// Also do domain WHOIS
		s.lookupDomainWHOIS(ctx, target)
	}

	// Get related prefixes from BGP
	if s.results.ASNInfo != nil && s.results.ASNInfo.ASN != "" {
		s.lookupASNPrefixes(ctx, s.results.ASNInfo.ASN)
	}

	return s.results, nil
}

// lookupIPASN looks up ASN information for an IP using multiple sources
func (s *ASNScanner) lookupIPASN(ctx context.Context, ip string) {
	// Try BGPView API
	s.lookupBGPView(ctx, ip)

	// Try ip-api.com as backup
	if s.results.ASNInfo == nil {
		s.lookupIPAPI(ctx, ip)
	}
}

// lookupBGPView uses BGPView API for ASN lookup
func (s *ASNScanner) lookupBGPView(ctx context.Context, ip string) {
	url := fmt.Sprintf("https://api.bgpview.io/ip/%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return
	}

	var result struct {
		Status string `json:"status"`
		Data   struct {
			IP       string `json:"ip"`
			Prefixes []struct {
				Prefix string `json:"prefix"`
				IP     string `json:"ip"`
				CIDR   int    `json:"cidr"`
				ASN    struct {
					ASN         int    `json:"asn"`
					Name        string `json:"name"`
					Description string `json:"description"`
					CountryCode string `json:"country_code"`
				} `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"prefixes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	if result.Status == "ok" && len(result.Data.Prefixes) > 0 {
		prefix := result.Data.Prefixes[0]
		s.mu.Lock()
		s.results.ASNInfo = &ASNInfo{
			ASN:         fmt.Sprintf("AS%d", prefix.ASN.ASN),
			Name:        prefix.ASN.Name,
			Description: prefix.ASN.Description,
			Country:     prefix.ASN.CountryCode,
		}

		// Collect all prefixes
		seen := make(map[string]bool)
		for _, p := range result.Data.Prefixes {
			if !seen[p.Prefix] {
				s.results.RelatedCIDRs = append(s.results.RelatedCIDRs, p.Prefix)
				seen[p.Prefix] = true
			}
		}
		s.mu.Unlock()
	}
}

// lookupIPAPI uses ip-api.com for ASN lookup
func (s *ASNScanner) lookupIPAPI(ctx context.Context, ip string) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,isp,org,as,asname,query", ip)

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}

	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		ASName      string `json:"asname"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	if result.Status == "success" {
		s.mu.Lock()
		// Parse ASN from "AS1234 Name" format
		asnParts := strings.SplitN(result.AS, " ", 2)
		asnNum := asnParts[0]

		s.results.ASNInfo = &ASNInfo{
			ASN:         asnNum,
			Name:        result.ASName,
			Description: result.Org,
			Country:     result.CountryCode,
		}
		s.mu.Unlock()
	}
}

// lookupASNPrefixes gets all prefixes announced by an ASN
func (s *ASNScanner) lookupASNPrefixes(ctx context.Context, asn string) {
	// Remove "AS" prefix if present
	asn = strings.TrimPrefix(asn, "AS")
	asn = strings.TrimPrefix(asn, "as")

	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return
	}

	var result struct {
		Status string `json:"status"`
		Data   struct {
			IPv4Prefixes []struct {
				Prefix      string `json:"prefix"`
				IP          string `json:"ip"`
				CIDR        int    `json:"cidr"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"ipv4_prefixes"`
			IPv6Prefixes []struct {
				Prefix      string `json:"prefix"`
				IP          string `json:"ip"`
				CIDR        int    `json:"cidr"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	if result.Status == "ok" {
		s.mu.Lock()
		seen := make(map[string]bool)

		// Add existing CIDRs to seen
		for _, cidr := range s.results.RelatedCIDRs {
			seen[cidr] = true
		}

		// Add IPv4 prefixes
		for _, p := range result.Data.IPv4Prefixes {
			if !seen[p.Prefix] {
				s.results.RelatedCIDRs = append(s.results.RelatedCIDRs, p.Prefix)
				s.results.BGPPrefixes = append(s.results.BGPPrefixes, BGPPrefix{
					Prefix:  p.Prefix,
					Name:    p.Name,
					Country: p.CountryCode,
				})
				seen[p.Prefix] = true
			}
		}

		// Count IPs
		if s.results.ASNInfo != nil {
			ipCount := 0
			for _, p := range result.Data.IPv4Prefixes {
				ipCount += 1 << (32 - p.CIDR)
			}
			s.results.ASNInfo.IPCount = ipCount
		}
		s.mu.Unlock()
	}
}

// lookupDomainWHOIS performs WHOIS lookup for a domain
func (s *ASNScanner) lookupDomainWHOIS(ctx context.Context, domain string) {
	// Use RDAP (Registration Data Access Protocol) for structured WHOIS
	s.lookupRDAP(ctx, domain)
}

// lookupRDAP uses RDAP for domain WHOIS
func (s *ASNScanner) lookupRDAP(ctx context.Context, domain string) {
	// Try common RDAP endpoints
	rdapURLs := []string{
		fmt.Sprintf("https://rdap.verisign.com/com/v1/domain/%s", domain),
		fmt.Sprintf("https://rdap.verisign.com/net/v1/domain/%s", domain),
		fmt.Sprintf("https://rdap.org/domain/%s", domain),
	}

	for _, url := range rdapURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/rdap+json")

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		var rdap struct {
			LDHName     string `json:"ldhName"`
			Status      []string `json:"status"`
			Entities    []struct {
				VCardArray []interface{} `json:"vcardArray"`
				Roles      []string      `json:"roles"`
			} `json:"entities"`
			Nameservers []struct {
				LDHName string `json:"ldhName"`
			} `json:"nameservers"`
			Events []struct {
				EventAction string `json:"eventAction"`
				EventDate   string `json:"eventDate"`
			} `json:"events"`
		}

		if err := json.Unmarshal(body, &rdap); err != nil {
			continue
		}

		s.mu.Lock()
		whois := &WHOISInfo{
			Domain: rdap.LDHName,
			Status: rdap.Status,
		}

		// Extract nameservers
		for _, ns := range rdap.Nameservers {
			whois.Nameservers = append(whois.Nameservers, ns.LDHName)
		}

		// Extract dates
		for _, event := range rdap.Events {
			switch event.EventAction {
			case "registration":
				whois.Created = event.EventDate
			case "expiration":
				whois.Expires = event.EventDate
			case "last changed":
				whois.Updated = event.EventDate
			}
		}

		// Extract organization from entities
		for _, entity := range rdap.Entities {
			for _, role := range entity.Roles {
				if role == "registrant" || role == "registrar" {
					if len(entity.VCardArray) > 0 {
						whois.Organization = s.extractVCardOrg(entity.VCardArray)
						if role == "registrar" {
							whois.Registrar = whois.Organization
						}
					}
				}
			}
		}

		s.results.WHOISInfo = whois
		s.mu.Unlock()
		return
	}
}

// extractVCardOrg extracts organization from vCard array
func (s *ASNScanner) extractVCardOrg(vcardArray []interface{}) string {
	if len(vcardArray) < 2 {
		return ""
	}

	props, ok := vcardArray[1].([]interface{})
	if !ok {
		return ""
	}

	for _, prop := range props {
		propArr, ok := prop.([]interface{})
		if !ok || len(propArr) < 4 {
			continue
		}

		propName, ok := propArr[0].(string)
		if !ok {
			continue
		}

		if propName == "fn" || propName == "org" {
			if val, ok := propArr[3].(string); ok {
				return val
			}
		}
	}

	return ""
}

// ExtractEmails extracts email addresses from WHOIS data
func (s *ASNScanner) ExtractEmails(raw string) []string {
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	matches := emailRegex.FindAllString(raw, -1)

	// Deduplicate
	seen := make(map[string]bool)
	unique := []string{}
	for _, email := range matches {
		email = strings.ToLower(email)
		if !seen[email] {
			seen[email] = true
			unique = append(unique, email)
		}
	}

	return unique
}

// GenerateReport creates a human-readable report
func (s *ASNScanner) GenerateReport() string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                 ASN/WHOIS ENUMERATION                        ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Target: %s\n\n", s.results.Target))

	if s.results.ASNInfo != nil {
		sb.WriteString("🌐 ASN INFORMATION:\n")
		sb.WriteString(fmt.Sprintf("  ASN: %s\n", s.results.ASNInfo.ASN))
		sb.WriteString(fmt.Sprintf("  Name: %s\n", s.results.ASNInfo.Name))
		if s.results.ASNInfo.Description != "" {
			sb.WriteString(fmt.Sprintf("  Description: %s\n", s.results.ASNInfo.Description))
		}
		sb.WriteString(fmt.Sprintf("  Country: %s\n", s.results.ASNInfo.Country))
		if s.results.ASNInfo.IPCount > 0 {
			sb.WriteString(fmt.Sprintf("  IP Count: %d\n", s.results.ASNInfo.IPCount))
		}
		sb.WriteString("\n")
	}

	if s.results.WHOISInfo != nil {
		sb.WriteString("📋 WHOIS INFORMATION:\n")
		if s.results.WHOISInfo.Domain != "" {
			sb.WriteString(fmt.Sprintf("  Domain: %s\n", s.results.WHOISInfo.Domain))
		}
		if s.results.WHOISInfo.Registrar != "" {
			sb.WriteString(fmt.Sprintf("  Registrar: %s\n", s.results.WHOISInfo.Registrar))
		}
		if s.results.WHOISInfo.Organization != "" {
			sb.WriteString(fmt.Sprintf("  Organization: %s\n", s.results.WHOISInfo.Organization))
		}
		if s.results.WHOISInfo.Created != "" {
			sb.WriteString(fmt.Sprintf("  Created: %s\n", s.results.WHOISInfo.Created))
		}
		if s.results.WHOISInfo.Updated != "" {
			sb.WriteString(fmt.Sprintf("  Updated: %s\n", s.results.WHOISInfo.Updated))
		}
		if s.results.WHOISInfo.Expires != "" {
			sb.WriteString(fmt.Sprintf("  Expires: %s\n", s.results.WHOISInfo.Expires))
		}
		if len(s.results.WHOISInfo.Nameservers) > 0 {
			sb.WriteString("  Nameservers:\n")
			for _, ns := range s.results.WHOISInfo.Nameservers {
				sb.WriteString(fmt.Sprintf("    • %s\n", ns))
			}
		}
		if len(s.results.WHOISInfo.Status) > 0 {
			sb.WriteString("  Status:\n")
			for _, status := range s.results.WHOISInfo.Status {
				sb.WriteString(fmt.Sprintf("    • %s\n", status))
			}
		}
		sb.WriteString("\n")
	}

	if len(s.results.RelatedCIDRs) > 0 {
		sb.WriteString("🔍 RELATED IP RANGES (BGP Prefixes):\n")
		// Show first 20 prefixes
		shown := 0
		for _, cidr := range s.results.RelatedCIDRs {
			if shown >= 20 {
				sb.WriteString(fmt.Sprintf("  ... and %d more prefixes\n", len(s.results.RelatedCIDRs)-20))
				break
			}
			sb.WriteString(fmt.Sprintf("  • %s\n", cidr))
			shown++
		}
		sb.WriteString(fmt.Sprintf("\nTotal prefixes: %d\n", len(s.results.RelatedCIDRs)))
	}

	return sb.String()
}
