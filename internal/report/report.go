package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"pentestai/internal/exploit"
	"pentestai/internal/recon"
	"pentestai/internal/webapp"
)

type Report struct {
	Title       string
	Target      string
	StartTime   time.Time
	EndTime     time.Time
	Executive   ExecutiveSummary
	Hosts       []recon.Host
	WebFindings []webapp.Finding
	Exploits    []ExploitResult
	Credentials []exploit.Credential

	// Enhanced vulnerability intelligence
	VulnDetails []VulnDetail `json:"vulnerability_details,omitempty"`
}

// VulnDetail contains enriched vulnerability information
type VulnDetail struct {
	CVE              string   `json:"cve"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	CVSSScore        float64  `json:"cvss_score"`
	CVSSSeverity     string   `json:"cvss_severity"`
	CVSSVector       string   `json:"cvss_vector,omitempty"`
	AffectedProducts []string `json:"affected_products,omitempty"`
	HasPublicExploit bool     `json:"has_public_exploit"`
	ExploitIDs       []string `json:"exploit_ids,omitempty"` // Exploit-DB IDs
	Remediation      string   `json:"remediation"`
	PatchURLs        []string `json:"patch_urls,omitempty"`
	References       []string `json:"references,omitempty"`
}

type ExecutiveSummary struct {
	TotalHosts       int
	TotalPorts       int
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
	InfoFindings     int
	RiskRating       string
}

type ExploitResult struct {
	Module    string
	Target    string
	Success   bool
	Output    string
	Timestamp time.Time
}

func NewReport(title, target string) *Report {
	return &Report{
		Title:     title,
		Target:    target,
		StartTime: time.Now(),
	}
}

func (r *Report) AddHost(host recon.Host) {
	r.Hosts = append(r.Hosts, host)
	r.Executive.TotalHosts++
	r.Executive.TotalPorts += len(host.Ports)
}

func (r *Report) AddWebFinding(finding webapp.Finding) {
	r.WebFindings = append(r.WebFindings, finding)

	switch strings.ToLower(finding.Severity) {
	case "critical":
		r.Executive.CriticalFindings++
	case "high":
		r.Executive.HighFindings++
	case "medium":
		r.Executive.MediumFindings++
	case "low":
		r.Executive.LowFindings++
	default:
		r.Executive.InfoFindings++
	}

	r.updateRiskRating()
}

func (r *Report) AddExploitResult(result *exploit.ExploitResult) {
	r.Exploits = append(r.Exploits, ExploitResult{
		Module:    result.Module,
		Target:    result.Target,
		Success:   result.Success,
		Output:    result.Output,
		Timestamp: result.EndTime,
	})

	r.Credentials = append(r.Credentials, result.Credentials...)
}

// AddVulnDetail adds enriched vulnerability information to the report
func (r *Report) AddVulnDetail(detail VulnDetail) {
	// Check for duplicates by CVE
	for i, existing := range r.VulnDetails {
		if existing.CVE == detail.CVE {
			// Merge information
			if detail.CVSSScore > 0 {
				r.VulnDetails[i].CVSSScore = detail.CVSSScore
			}
			if detail.CVSSSeverity != "" {
				r.VulnDetails[i].CVSSSeverity = detail.CVSSSeverity
			}
			if detail.Remediation != "" {
				r.VulnDetails[i].Remediation = detail.Remediation
			}
			r.VulnDetails[i].PatchURLs = appendUniqueStrings(r.VulnDetails[i].PatchURLs, detail.PatchURLs...)
			r.VulnDetails[i].ExploitIDs = appendUniqueStrings(r.VulnDetails[i].ExploitIDs, detail.ExploitIDs...)
			if detail.HasPublicExploit {
				r.VulnDetails[i].HasPublicExploit = true
			}
			return
		}
	}
	r.VulnDetails = append(r.VulnDetails, detail)
}

func appendUniqueStrings(slice []string, items ...string) []string {
	seen := make(map[string]bool)
	for _, s := range slice {
		seen[s] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}

func (r *Report) updateRiskRating() {
	if r.Executive.CriticalFindings > 0 {
		r.Executive.RiskRating = "Critical"
	} else if r.Executive.HighFindings > 0 {
		r.Executive.RiskRating = "High"
	} else if r.Executive.MediumFindings > 0 {
		r.Executive.RiskRating = "Medium"
	} else if r.Executive.LowFindings > 0 {
		r.Executive.RiskRating = "Low"
	} else {
		r.Executive.RiskRating = "Informational"
	}
}

func (r *Report) Finalize() {
	r.EndTime = time.Now()
}

func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r *Report) SaveJSON(filename string) error {
	data, err := r.ToJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (r *Report) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s\n\n", r.Title))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", r.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", r.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %v\n\n", r.EndTime.Sub(r.StartTime).Round(time.Second)))

	// CRITICAL: Exposed Credentials Section (shown first if any found)
	if len(r.Credentials) > 0 {
		sb.WriteString("## ⚠️ CRITICAL: EXPOSED CREDENTIALS ⚠️\n\n")
		sb.WriteString("**The following credentials were extracted during testing. These represent a CRITICAL security risk.**\n\n")
		sb.WriteString("| Username | Password | Type | Source |\n")
		sb.WriteString("|----------|----------|------|--------|\n")
		for _, cred := range r.Credentials {
			pass := cred.Password
			if pass == "" && cred.Hash != "" {
				pass = cred.Hash[:min(20, len(cred.Hash))] + "... (hash)"
			}
			sb.WriteString(fmt.Sprintf("| **%s** | `%s` | %s | %s |\n",
				cred.Username, pass, cred.Type, cred.Source))
		}
		sb.WriteString("\n**Immediate Action Required:** All exposed passwords must be changed immediately.\n\n")
		sb.WriteString("---\n\n")
	}

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Value |\n"))
	sb.WriteString(fmt.Sprintf("|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Overall Risk Rating | **%s** |\n", r.Executive.RiskRating))
	sb.WriteString(fmt.Sprintf("| Credentials Exposed | **%d** |\n", len(r.Credentials)))
	sb.WriteString(fmt.Sprintf("| Total Hosts | %d |\n", r.Executive.TotalHosts))
	sb.WriteString(fmt.Sprintf("| Open Ports | %d |\n", r.Executive.TotalPorts))
	sb.WriteString(fmt.Sprintf("| Critical Findings | %d |\n", r.Executive.CriticalFindings))
	sb.WriteString(fmt.Sprintf("| High Findings | %d |\n", r.Executive.HighFindings))
	sb.WriteString(fmt.Sprintf("| Medium Findings | %d |\n", r.Executive.MediumFindings))
	sb.WriteString(fmt.Sprintf("| Low Findings | %d |\n", r.Executive.LowFindings))
	sb.WriteString("\n")

	// Host Discovery
	if len(r.Hosts) > 0 {
		sb.WriteString("## Host Discovery\n\n")
		for _, host := range r.Hosts {
			sb.WriteString(fmt.Sprintf("### %s\n\n", host.IP))
			if host.Hostname != "" {
				sb.WriteString(fmt.Sprintf("**Hostname:** %s\n\n", host.Hostname))
			}
			if host.OS != nil && host.OS.Name != "" {
				sb.WriteString(fmt.Sprintf("**OS:** %s\n\n", host.OS.Name))
			}

			if len(host.Ports) > 0 {
				sb.WriteString("| Port | Protocol | Service | Version |\n")
				sb.WriteString("|------|----------|---------|--------|\n")
				for _, port := range host.Ports {
					version := port.Service.Product
					if port.Service.Version != "" {
						version += " " + port.Service.Version
					}
					sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n",
						port.Number, port.Protocol, port.Service.Name, version))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Web Vulnerabilities
	if len(r.WebFindings) > 0 {
		sb.WriteString("## Web Vulnerabilities\n\n")
		for i, finding := range r.WebFindings {
			sb.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, finding.Type, finding.Severity))
			sb.WriteString(fmt.Sprintf("**URL:** %s\n\n", finding.URL))
			if finding.Parameter != "" {
				sb.WriteString(fmt.Sprintf("**Parameter:** `%s`\n\n", finding.Parameter))
			}
			if finding.Payload != "" {
				sb.WriteString(fmt.Sprintf("**Payload:** `%s`\n\n", finding.Payload))
			}
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", finding.Description))
			if finding.Evidence != "" {
				sb.WriteString(fmt.Sprintf("**Evidence:** %s\n\n", finding.Evidence))
			}
			if finding.Remediation != "" {
				sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", finding.Remediation))
			}
		}
	}

	// Vulnerability Intelligence (CVE Details)
	if len(r.VulnDetails) > 0 {
		sb.WriteString("## Vulnerability Intelligence\n\n")
		sb.WriteString("The following CVEs were identified and enriched with data from NVD and Exploit-DB:\n\n")

		// Sort by CVSS score (highest first)
		sortedVulns := make([]VulnDetail, len(r.VulnDetails))
		copy(sortedVulns, r.VulnDetails)
		for i := 0; i < len(sortedVulns)-1; i++ {
			for j := i + 1; j < len(sortedVulns); j++ {
				if sortedVulns[j].CVSSScore > sortedVulns[i].CVSSScore {
					sortedVulns[i], sortedVulns[j] = sortedVulns[j], sortedVulns[i]
				}
			}
		}

		for i, vuln := range sortedVulns {
			// Severity emoji
			severityEmoji := "ℹ️"
			switch strings.ToUpper(vuln.CVSSSeverity) {
			case "CRITICAL":
				severityEmoji = "🔴"
			case "HIGH":
				severityEmoji = "🟠"
			case "MEDIUM":
				severityEmoji = "🟡"
			case "LOW":
				severityEmoji = "🟢"
			}

			sb.WriteString(fmt.Sprintf("### %d. %s %s\n\n", i+1, severityEmoji, vuln.CVE))
			sb.WriteString(fmt.Sprintf("**Title:** %s\n\n", vuln.Title))

			// CVSS Score
			if vuln.CVSSScore > 0 {
				sb.WriteString(fmt.Sprintf("**CVSS Score:** %.1f (%s)\n\n", vuln.CVSSScore, vuln.CVSSSeverity))
				if vuln.CVSSVector != "" {
					sb.WriteString(fmt.Sprintf("**Vector:** `%s`\n\n", vuln.CVSSVector))
				}
			}

			// Description
			if vuln.Description != "" {
				sb.WriteString(fmt.Sprintf("**Description:**\n%s\n\n", vuln.Description))
			}

			// Public Exploit Warning
			if vuln.HasPublicExploit {
				sb.WriteString("**⚠️ PUBLIC EXPLOIT AVAILABLE**\n\n")
				if len(vuln.ExploitIDs) > 0 {
					sb.WriteString("Exploit-DB IDs: ")
					for j, eid := range vuln.ExploitIDs {
						if j > 0 {
							sb.WriteString(", ")
						}
						sb.WriteString(fmt.Sprintf("[%s](https://www.exploit-db.com/exploits/%s)", eid, strings.TrimPrefix(eid, "EDB-")))
					}
					sb.WriteString("\n\n")
				}
			}

			// Affected Products
			if len(vuln.AffectedProducts) > 0 {
				sb.WriteString("**Affected Products:**\n")
				for _, p := range vuln.AffectedProducts {
					sb.WriteString(fmt.Sprintf("- %s\n", p))
				}
				sb.WriteString("\n")
			}

			// Remediation
			if vuln.Remediation != "" {
				sb.WriteString("**Remediation:**\n")
				sb.WriteString(fmt.Sprintf("%s\n\n", vuln.Remediation))
			}

			// Patch URLs
			if len(vuln.PatchURLs) > 0 {
				sb.WriteString("**Patch/Advisory Links:**\n")
				for _, url := range vuln.PatchURLs {
					sb.WriteString(fmt.Sprintf("- %s\n", url))
				}
				sb.WriteString("\n")
			}

			// References (limit to 3)
			if len(vuln.References) > 0 {
				sb.WriteString("**References:**\n")
				limit := len(vuln.References)
				if limit > 3 {
					limit = 3
				}
				for j := 0; j < limit; j++ {
					sb.WriteString(fmt.Sprintf("- %s\n", vuln.References[j]))
				}
				if len(vuln.References) > 3 {
					sb.WriteString(fmt.Sprintf("- ... and %d more\n", len(vuln.References)-3))
				}
				sb.WriteString("\n")
			}

			sb.WriteString("---\n\n")
		}

		// Remediation Priority Summary
		sb.WriteString("### Remediation Priority Summary\n\n")
		critical, high, medium, low := 0, 0, 0, 0
		hasExploit := 0
		for _, v := range r.VulnDetails {
			switch strings.ToUpper(v.CVSSSeverity) {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			}
			if v.HasPublicExploit {
				hasExploit++
			}
		}
		sb.WriteString("| Priority | Count | Action |\n")
		sb.WriteString("|----------|-------|--------|\n")
		if critical > 0 {
			sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d | **Fix immediately** |\n", critical))
		}
		if high > 0 {
			sb.WriteString(fmt.Sprintf("| 🟠 High | %d | Fix within 24-48 hours |\n", high))
		}
		if medium > 0 {
			sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d | Schedule for patching |\n", medium))
		}
		if low > 0 {
			sb.WriteString(fmt.Sprintf("| 🟢 Low | %d | Address in next maintenance |\n", low))
		}
		sb.WriteString("\n")

		if hasExploit > 0 {
			sb.WriteString(fmt.Sprintf("**⚠️ WARNING:** %d vulnerabilities have public exploits available. These should be prioritized!\n\n", hasExploit))
		}
	}

	// Exploit Results
	if len(r.Exploits) > 0 {
		sb.WriteString("## Exploitation Results\n\n")
		for _, exp := range r.Exploits {
			status := "Failed"
			if exp.Success {
				status = "**Success**"
			}
			sb.WriteString(fmt.Sprintf("### %s\n\n", exp.Module))
			sb.WriteString(fmt.Sprintf("- **Target:** %s\n", exp.Target))
			sb.WriteString(fmt.Sprintf("- **Status:** %s\n", status))
			sb.WriteString(fmt.Sprintf("- **Time:** %s\n\n", exp.Timestamp.Format("15:04:05")))
			if exp.Output != "" && len(exp.Output) < 1000 {
				sb.WriteString("```\n")
				sb.WriteString(exp.Output)
				sb.WriteString("\n```\n\n")
			}
		}
	}

	// Credentials
	if len(r.Credentials) > 0 {
		sb.WriteString("## Discovered Credentials\n\n")
		sb.WriteString("| Username | Password/Hash | Type | Source |\n")
		sb.WriteString("|----------|---------------|------|--------|\n")
		for _, cred := range r.Credentials {
			pass := cred.Password
			if cred.Hash != "" {
				pass = cred.Hash[:min(20, len(cred.Hash))] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				cred.Username, pass, cred.Type, cred.Source))
		}
		sb.WriteString("\n")
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString("*Generated by PentestAI*\n")

	return sb.String()
}

func (r *Report) SaveMarkdown(filename string) error {
	return os.WriteFile(filename, []byte(r.ToMarkdown()), 0644)
}

func (r *Report) ToHTML() string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>` + r.Title + `</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
        h2 { color: #666; margin-top: 30px; }
        h3 { color: #888; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f5f5; }
        .critical { background-color: #d32f2f; color: white; padding: 2px 8px; border-radius: 3px; }
        .high { background-color: #f57c00; color: white; padding: 2px 8px; border-radius: 3px; }
        .medium { background-color: #fbc02d; padding: 2px 8px; border-radius: 3px; }
        .low { background-color: #1976d2; color: white; padding: 2px 8px; border-radius: 3px; }
        .info { background-color: #455a64; color: white; padding: 2px 8px; border-radius: 3px; }
        .success { color: #4caf50; font-weight: bold; }
        .failed { color: #f44336; }
        pre { background-color: #f5f5f5; padding: 10px; overflow-x: auto; }
        .summary-box { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .summary-item { background: #f5f5f5; padding: 15px; border-radius: 5px; min-width: 150px; }
        .summary-item h4 { margin: 0 0 5px 0; color: #666; }
        .summary-item .value { font-size: 24px; font-weight: bold; }
    </style>
</head>
<body>
`)

	sb.WriteString(fmt.Sprintf("<h1>%s</h1>\n", r.Title))
	sb.WriteString(fmt.Sprintf("<p><strong>Target:</strong> %s</p>\n", r.Target))
	sb.WriteString(fmt.Sprintf("<p><strong>Date:</strong> %s</p>\n", r.StartTime.Format("2006-01-02 15:04:05")))

	// CRITICAL: Credentials at top if found
	if len(r.Credentials) > 0 {
		sb.WriteString(`<div style="background:#ffebee;border:3px solid #d32f2f;border-radius:8px;padding:20px;margin:20px 0;">`)
		sb.WriteString(`<h2 style="color:#d32f2f;margin-top:0;">⚠️ CRITICAL: EXPOSED CREDENTIALS</h2>`)
		sb.WriteString(`<p><strong>The following credentials were extracted during testing. These represent a CRITICAL security risk.</strong></p>`)
		sb.WriteString("<table style=\"background:white;\">\n<tr><th>Username</th><th>Password</th><th>Type</th><th>Source</th></tr>\n")
		for _, cred := range r.Credentials {
			pass := cred.Password
			if pass == "" && cred.Hash != "" {
				pass = cred.Hash[:min(20, len(cred.Hash))] + "..."
			}
			sb.WriteString(fmt.Sprintf("<tr><td><strong>%s</strong></td><td><code style=\"background:#fff3e0;padding:2px 6px;\">%s</code></td><td>%s</td><td>%s</td></tr>\n",
				cred.Username, pass, cred.Type, cred.Source))
		}
		sb.WriteString("</table>\n")
		sb.WriteString(`<p style="color:#d32f2f;font-weight:bold;margin-bottom:0;">⚡ Immediate Action Required: All exposed passwords must be changed immediately.</p>`)
		sb.WriteString("</div>\n")
	}

	// Summary boxes
	sb.WriteString(`<div class="summary-box">`)
	sb.WriteString(fmt.Sprintf(`<div class="summary-item"><h4>Risk Rating</h4><div class="value %s">%s</div></div>`,
		strings.ToLower(r.Executive.RiskRating), r.Executive.RiskRating))
	sb.WriteString(fmt.Sprintf(`<div class="summary-item"><h4>Hosts</h4><div class="value">%d</div></div>`,
		r.Executive.TotalHosts))
	sb.WriteString(fmt.Sprintf(`<div class="summary-item"><h4>Ports</h4><div class="value">%d</div></div>`,
		r.Executive.TotalPorts))
	sb.WriteString(fmt.Sprintf(`<div class="summary-item"><h4>Critical</h4><div class="value critical">%d</div></div>`,
		r.Executive.CriticalFindings))
	sb.WriteString(fmt.Sprintf(`<div class="summary-item"><h4>High</h4><div class="value high">%d</div></div>`,
		r.Executive.HighFindings))
	sb.WriteString("</div>\n")

	// Hosts
	if len(r.Hosts) > 0 {
		sb.WriteString("<h2>Discovered Hosts</h2>\n")
		for _, host := range r.Hosts {
			sb.WriteString(fmt.Sprintf("<h3>%s", host.IP))
			if host.Hostname != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", host.Hostname))
			}
			sb.WriteString("</h3>\n")

			if len(host.Ports) > 0 {
				sb.WriteString("<table>\n<tr><th>Port</th><th>Service</th><th>Version</th></tr>\n")
				for _, port := range host.Ports {
					version := port.Service.Product
					if port.Service.Version != "" {
						version += " " + port.Service.Version
					}
					sb.WriteString(fmt.Sprintf("<tr><td>%d/%s</td><td>%s</td><td>%s</td></tr>\n",
						port.Number, port.Protocol, port.Service.Name, version))
				}
				sb.WriteString("</table>\n")
			}
		}
	}

	// Vulnerabilities
	if len(r.WebFindings) > 0 {
		sb.WriteString("<h2>Vulnerabilities</h2>\n")
		for _, finding := range r.WebFindings {
			sb.WriteString(fmt.Sprintf("<h3><span class=\"%s\">%s</span> %s</h3>\n",
				strings.ToLower(finding.Severity), finding.Severity, finding.Type))
			sb.WriteString(fmt.Sprintf("<p><strong>URL:</strong> %s</p>\n", finding.URL))
			if finding.Parameter != "" {
				sb.WriteString(fmt.Sprintf("<p><strong>Parameter:</strong> <code>%s</code></p>\n", finding.Parameter))
			}
			sb.WriteString(fmt.Sprintf("<p>%s</p>\n", finding.Description))
			if finding.Remediation != "" {
				sb.WriteString(fmt.Sprintf("<p><strong>Remediation:</strong> %s</p>\n", finding.Remediation))
			}
		}
	}

	// Credentials
	if len(r.Credentials) > 0 {
		sb.WriteString("<h2>Discovered Credentials</h2>\n")
		sb.WriteString("<table>\n<tr><th>Username</th><th>Password</th><th>Type</th><th>Source</th></tr>\n")
		for _, cred := range r.Credentials {
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				cred.Username, cred.Password, cred.Type, cred.Source))
		}
		sb.WriteString("</table>\n")
	}

	sb.WriteString("<hr>\n<p><em>Generated by PentestAI</em></p>\n</body>\n</html>")

	return sb.String()
}

func (r *Report) SaveHTML(filename string) error {
	return os.WriteFile(filename, []byte(r.ToHTML()), 0644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ScanResult represents a single test result for PDF export
type ScanResult struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Results string `json:"results"`
}

// VulnerabilityEntry represents a vulnerability for PDF export
type VulnerabilityEntry struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Details     string `json:"details"`
}

// CredentialEntry represents a credential for PDF export
type CredentialEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Service  string `json:"service"`
}

// PDFExportData represents the data structure for PDF generation
type PDFExportData struct {
	Target          string               `json:"target"`
	Date            string               `json:"date"`
	Tests           []ScanResult         `json:"tests"`
	Vulnerabilities []VulnerabilityEntry `json:"vulnerabilities"`
	Credentials     []CredentialEntry    `json:"credentials"`
}

// ToPDFExport converts the report to PDF export format
func (r *Report) ToPDFExport() *PDFExportData {
	data := &PDFExportData{
		Target:          r.Target,
		Date:            r.StartTime.Format("2006-01-02"),
		Tests:           make([]ScanResult, 0),
		Vulnerabilities: make([]VulnerabilityEntry, 0),
		Credentials:     make([]CredentialEntry, 0),
	}

	// Convert exploit results to scan results
	for _, exp := range r.Exploits {
		data.Tests = append(data.Tests, ScanResult{
			Name:    exp.Module,
			Action:  exp.Module,
			Target:  exp.Target,
			Success: exp.Success,
			Output:  exp.Output,
		})
	}

	// Convert web findings to vulnerabilities
	for _, finding := range r.WebFindings {
		data.Vulnerabilities = append(data.Vulnerabilities, VulnerabilityEntry{
			Type:        finding.Type,
			Name:        finding.Type,
			Severity:    strings.ToLower(finding.Severity),
			Target:      finding.URL,
			Description: finding.Description,
			Details:     finding.Evidence,
		})
	}

	// Convert credentials
	for _, cred := range r.Credentials {
		data.Credentials = append(data.Credentials, CredentialEntry{
			Username: cred.Username,
			Password: cred.Password,
			Hash:     cred.Hash,
			Type:     cred.Type,
			Source:   cred.Source,
		})
	}

	return data
}

// SavePDFExport saves the report in PDF export JSON format
func (r *Report) SavePDFExport(filename string) error {
	data := r.ToPDFExport()
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, jsonData, 0644)
}
