package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pentestai/internal/audit"
	"pentestai/internal/evidence"
	"pentestai/internal/remediation"
	"pentestai/internal/safe"
)

// ProfessionalReport is an executive-quality penetration test report
type ProfessionalReport struct {
	// Metadata
	Title          string    `json:"title"`
	EngagementID   string    `json:"engagement_id"`
	CustomerName   string    `json:"customer_name"`
	PreparedBy     string    `json:"prepared_by"`
	PreparedFor    string    `json:"prepared_for"`
	ReportDate     time.Time `json:"report_date"`
	Classification string    `json:"classification"`
	Version        string    `json:"version"`

	// Engagement Details
	EngagementType string    `json:"engagement_type"`
	StartDate      time.Time `json:"start_date"`
	EndDate        time.Time `json:"end_date"`
	Scope          []string  `json:"scope"`
	Methodology    string    `json:"methodology"`
	SafetyLevel    string    `json:"safety_level"`

	// Executive Summary
	ExecutiveSummary *ExecutiveBrief `json:"executive_summary"`

	// Findings
	Findings        []FindingDetail  `json:"findings"`
	FindingsSummary *FindingsSummary `json:"findings_summary"`

	// Technical Details
	ReconResults *ReconSummary  `json:"recon_results,omitempty"`
	Evidence     []EvidenceItem `json:"evidence,omitempty"`

	// Recommendations
	Recommendations []RecommendationItem `json:"recommendations"`
	RemediationPlan *RemediationPlan     `json:"remediation_plan"`

	// Appendices
	AuditLog           []audit.AuditEvent `json:"audit_log,omitempty"`
	Methodology_Detail string             `json:"methodology_detail,omitempty"`
}

// ExecutiveBrief provides high-level summary for executives
type ExecutiveBrief struct {
	OverallRisk      string `json:"overall_risk"`
	RiskScore        int    `json:"risk_score"` // 0-100
	KeyFindings      string `json:"key_findings"`
	BusinessImpact   string `json:"business_impact"`
	ImmediateActions string `json:"immediate_actions"`
	StrategicOutlook string `json:"strategic_outlook"`
}

// FindingDetail provides comprehensive finding information
type FindingDetail struct {
	ID              string                      `json:"id"`
	Title           string                      `json:"title"`
	Severity        string                      `json:"severity"`
	CVSS            float64                     `json:"cvss,omitempty"`
	Status          string                      `json:"status"` // Confirmed, Potential, Informational
	AffectedAssets  []string                    `json:"affected_assets"`
	Description     string                      `json:"description"`
	TechnicalDetail string                      `json:"technical_detail"`
	Evidence        []string                    `json:"evidence_refs"`
	Impact          string                      `json:"impact"`
	Likelihood      string                      `json:"likelihood"`
	Remediation     *remediation.Recommendation `json:"remediation"`
	References      []string                    `json:"references"`
	CWE             []string                    `json:"cwe"`
	CVE             []string                    `json:"cve,omitempty"`
}

// FindingsSummary provides statistics
type FindingsSummary struct {
	Total         int            `json:"total"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	ByStatus      map[string]int `json:"by_status"`
	TopCategories []string       `json:"top_categories"`
}

// ReconSummary summarizes reconnaissance results
type ReconSummary struct {
	HostsDiscovered int      `json:"hosts_discovered"`
	PortsOpen       int      `json:"ports_open"`
	ServicesFound   int      `json:"services_found"`
	TopServices     []string `json:"top_services"`
	ExposedServices []string `json:"exposed_services"`
}

// EvidenceItem for report
type EvidenceItem struct {
	ID          string `json:"id"`
	FindingRef  string `json:"finding_ref"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Data        string `json:"data,omitempty"`
}

// RecommendationItem for prioritized fixes
type RecommendationItem struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Effort      string `json:"effort"`
	Impact      string `json:"impact"`
	Timeline    string `json:"timeline"`
}

// RemediationPlan provides structured fix guidance
type RemediationPlan struct {
	ImmediatePriority []string `json:"immediate"`   // Fix within 24-48 hours
	ShortTerm         []string `json:"short_term"`  // Fix within 1-2 weeks
	MediumTerm        []string `json:"medium_term"` // Fix within 1-3 months
	LongTerm          []string `json:"long_term"`   // Ongoing improvements
}

// GenerateProfessionalReport creates a comprehensive report from assessment results
func GenerateProfessionalReport(result *safe.AssessmentResult, evidenceItems []evidence.Evidence) *ProfessionalReport {
	report := &ProfessionalReport{
		Title:          fmt.Sprintf("Penetration Test Report - %s", result.CustomerName),
		EngagementID:   result.EngagementID,
		CustomerName:   result.CustomerName,
		PreparedBy:     "PentestAI Automated Assessment",
		PreparedFor:    result.CustomerName,
		ReportDate:     time.Now(),
		Classification: "CONFIDENTIAL",
		Version:        "1.0",
		EngagementType: "Automated Penetration Test",
		StartDate:      result.StartTime,
		EndDate:        result.EndTime,
		Scope:          result.Scope,
		Methodology:    "PTES (Penetration Testing Execution Standard)",
		SafetyLevel:    result.SafetyLevel,
		AuditLog:       result.AuditLog,
	}

	// Generate executive summary
	report.ExecutiveSummary = generateExecutiveSummary(result)

	// Convert findings
	report.Findings = convertFindings(result.Findings)
	report.FindingsSummary = generateFindingsSummary(report.Findings)

	// Convert evidence
	for _, ev := range evidenceItems {
		report.Evidence = append(report.Evidence, EvidenceItem{
			ID:          ev.ID,
			FindingRef:  ev.FindingRef,
			Type:        string(ev.Type),
			Description: ev.Description,
			Data:        ev.Data,
		})
	}

	// Generate recommendations
	report.Recommendations = generateRecommendations(result.Findings)
	report.RemediationPlan = generateRemediationPlan(result.Findings)

	// Add methodology detail
	report.Methodology_Detail = getMethodologyDetail()

	return report
}

func generateExecutiveSummary(result *safe.AssessmentResult) *ExecutiveBrief {
	summary := result.Summary

	riskScore := calculateRiskScore(summary)
	riskLevel := summary.RiskRating

	keyFindings := generateKeyFindingsText(summary)
	businessImpact := generateBusinessImpactText(summary)
	immediateActions := generateImmediateActionsText(summary)
	strategicOutlook := generateStrategicOutlookText(summary)

	return &ExecutiveBrief{
		OverallRisk:      riskLevel,
		RiskScore:        riskScore,
		KeyFindings:      keyFindings,
		BusinessImpact:   businessImpact,
		ImmediateActions: immediateActions,
		StrategicOutlook: strategicOutlook,
	}
}

func calculateRiskScore(summary *safe.AssessmentSummary) int {
	// Weighted scoring: Critical=25, High=15, Medium=8, Low=3
	score := summary.CriticalCount*25 + summary.HighCount*15 +
		summary.MediumCount*8 + summary.LowCount*3

	// Cap at 100
	if score > 100 {
		score = 100
	}
	return score
}

func generateKeyFindingsText(summary *safe.AssessmentSummary) string {
	var parts []string

	if summary.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical vulnerabilities requiring immediate attention", summary.CriticalCount))
	}
	if summary.HighCount > 0 {
		parts = append(parts, fmt.Sprintf("%d high-severity issues that could lead to significant compromise", summary.HighCount))
	}
	if summary.CredentialsFound > 0 {
		parts = append(parts, fmt.Sprintf("%d instances of weak or default credentials discovered", summary.CredentialsFound))
	}
	if len(parts) == 0 {
		if summary.MediumCount > 0 {
			parts = append(parts, fmt.Sprintf("%d medium-severity findings identified", summary.MediumCount))
		} else {
			parts = append(parts, "No critical or high-severity vulnerabilities identified")
		}
	}

	return strings.Join(parts, ". ") + "."
}

func generateBusinessImpactText(summary *safe.AssessmentSummary) string {
	if summary.CriticalCount > 0 || summary.CredentialsFound > 0 {
		return "The identified vulnerabilities pose significant risk to business operations. " +
			"Exploitation could result in unauthorized access to sensitive systems, data breach, " +
			"regulatory non-compliance, and reputational damage. Immediate remediation is strongly recommended."
	}
	if summary.HighCount > 0 {
		return "Several high-severity vulnerabilities were identified that could impact business continuity. " +
			"While not immediately critical, these issues should be addressed promptly to prevent potential exploitation."
	}
	if summary.MediumCount > 0 {
		return "Medium-severity vulnerabilities were identified that represent moderate risk. " +
			"These should be addressed as part of regular security maintenance activities."
	}
	return "The overall security posture is acceptable. Continue regular security maintenance and monitoring."
}

func generateImmediateActionsText(summary *safe.AssessmentSummary) string {
	var actions []string

	if summary.CredentialsFound > 0 {
		actions = append(actions, "Change all default and weak credentials immediately")
	}
	if summary.CriticalCount > 0 {
		actions = append(actions, "Address critical vulnerabilities within 24-48 hours")
	}
	if summary.HighCount > 0 {
		actions = append(actions, "Prioritize remediation of high-severity findings within one week")
	}

	if len(actions) == 0 {
		return "No immediate actions required. Continue monitoring and maintain security hygiene."
	}

	return strings.Join(actions, "; ") + "."
}

func generateStrategicOutlookText(summary *safe.AssessmentSummary) string {
	return "Recommend implementing a continuous security monitoring program, regular vulnerability assessments, " +
		"and security awareness training. Consider implementing a Web Application Firewall (WAF) and " +
		"intrusion detection systems for defense in depth."
}

func convertFindings(findings []safe.Finding) []FindingDetail {
	var details []FindingDetail

	for _, f := range findings {
		detail := FindingDetail{
			ID:              f.ID,
			Title:           f.Title,
			Severity:        f.Severity,
			CVSS:            f.CVSS,
			Status:          "Confirmed",
			AffectedAssets:  []string{fmt.Sprintf("%s:%d", f.Target, f.Port)},
			Description:     f.Description,
			TechnicalDetail: generateTechnicalDetail(f),
			Impact:          getImpactByType(f.Type),
			Likelihood:      getLikelihood(f.Severity),
			Remediation:     f.Remediation,
			CWE:             getCWEByType(f.Type),
			CVE:             f.CVE,
		}

		if f.Remediation != nil {
			detail.References = f.Remediation.References
		}

		// Link evidence
		for _, ev := range f.Evidence {
			detail.Evidence = append(detail.Evidence, ev.ID)
		}

		details = append(details, detail)
	}

	// Sort by severity (Critical first)
	sort.Slice(details, func(i, j int) bool {
		return severityRank(details[i].Severity) > severityRank(details[j].Severity)
	})

	return details
}

func generateTechnicalDetail(f safe.Finding) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Target: %s\n", f.Target))
	if f.Port > 0 {
		sb.WriteString(fmt.Sprintf("Port: %d\n", f.Port))
	}
	if f.Service != "" {
		sb.WriteString(fmt.Sprintf("Service: %s\n", f.Service))
	}
	sb.WriteString(fmt.Sprintf("\nVulnerability Type: %s\n", f.Type))
	sb.WriteString(fmt.Sprintf("\n%s", f.Description))
	return sb.String()
}

func generateFindingsSummary(findings []FindingDetail) *FindingsSummary {
	summary := &FindingsSummary{
		Total:      len(findings),
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	categoryCount := make(map[string]int)

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByStatus[f.Status]++

		// Extract category from CWE or type
		category := "Other"
		if len(f.CWE) > 0 {
			category = f.CWE[0]
		}
		categoryCount[category]++
	}

	summary.ByCategory = categoryCount

	// Get top categories
	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range categoryCount {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	for i, kv := range sorted {
		if i >= 5 {
			break
		}
		summary.TopCategories = append(summary.TopCategories, kv.Key)
	}

	return summary
}

func generateRecommendations(findings []safe.Finding) []RecommendationItem {
	var recs []RecommendationItem
	seen := make(map[string]bool)
	priority := 1

	// Process by severity
	for _, severity := range []string{"Critical", "High", "Medium", "Low"} {
		for _, f := range findings {
			if f.Severity != severity {
				continue
			}
			if f.Remediation == nil {
				continue
			}
			if seen[f.Type] {
				continue
			}
			seen[f.Type] = true

			timeline := getTimeline(severity)
			recs = append(recs, RecommendationItem{
				Priority:    priority,
				Title:       f.Remediation.Title,
				Description: f.Remediation.QuickFix,
				Effort:      f.Remediation.EffortEstimate,
				Impact:      severity,
				Timeline:    timeline,
			})
			priority++
		}
	}

	return recs
}

func generateRemediationPlan(findings []safe.Finding) *RemediationPlan {
	plan := &RemediationPlan{}

	for _, f := range findings {
		if f.Remediation == nil {
			continue
		}
		action := fmt.Sprintf("%s: %s", f.Title, f.Remediation.QuickFix)

		switch f.Severity {
		case "Critical":
			plan.ImmediatePriority = append(plan.ImmediatePriority, action)
		case "High":
			plan.ShortTerm = append(plan.ShortTerm, action)
		case "Medium":
			plan.MediumTerm = append(plan.MediumTerm, action)
		default:
			plan.LongTerm = append(plan.LongTerm, action)
		}
	}

	return plan
}

// Helper functions

func severityRank(severity string) int {
	ranks := map[string]int{
		"Critical": 5,
		"High":     4,
		"Medium":   3,
		"Low":      2,
		"Info":     1,
	}
	return ranks[severity]
}

func getImpactByType(vulnType string) string {
	impacts := map[string]string{
		"sql_injection":       "Complete database compromise, data theft, authentication bypass",
		"xss":                 "Session hijacking, credential theft, malware distribution",
		"default_credentials": "Unauthorized system access, lateral movement",
		"lfi":                 "Source code disclosure, configuration exposure, potential RCE",
		"command_injection":   "Complete system compromise, remote code execution",
		"ssrf":                "Internal network access, cloud metadata exposure",
		"redis_unauth":        "Data theft, server compromise",
		"mongodb_unauth":      "Complete database access, data theft",
	}
	if impact, ok := impacts[strings.ToLower(strings.ReplaceAll(vulnType, " ", "_"))]; ok {
		return impact
	}
	return "Potential security breach and data exposure"
}

func getLikelihood(severity string) string {
	likelihoods := map[string]string{
		"Critical": "High - Easily exploitable with significant impact",
		"High":     "Medium-High - Exploitable with moderate effort",
		"Medium":   "Medium - Requires specific conditions or knowledge",
		"Low":      "Low - Difficult to exploit or limited impact",
	}
	return likelihoods[severity]
}

func getCWEByType(vulnType string) []string {
	cwes := map[string][]string{
		"sql_injection":       {"CWE-89"},
		"xss":                 {"CWE-79"},
		"default_credentials": {"CWE-521", "CWE-798"},
		"lfi":                 {"CWE-98", "CWE-22"},
		"command_injection":   {"CWE-78"},
		"ssrf":                {"CWE-918"},
		"redis_unauth":        {"CWE-306"},
		"mongodb_unauth":      {"CWE-306"},
		"ssl_weak":            {"CWE-326", "CWE-327"},
	}
	key := strings.ToLower(strings.ReplaceAll(vulnType, " ", "_"))
	if cwe, ok := cwes[key]; ok {
		return cwe
	}
	return []string{}
}

func getTimeline(severity string) string {
	timelines := map[string]string{
		"Critical": "Immediate (24-48 hours)",
		"High":     "Short-term (1-2 weeks)",
		"Medium":   "Medium-term (1-3 months)",
		"Low":      "Long-term (3-6 months)",
	}
	return timelines[severity]
}

func getMethodologyDetail() string {
	return `This penetration test was conducted following the Penetration Testing Execution Standard (PTES) methodology:

1. Pre-engagement Interactions
   - Scope definition and target identification
   - Rules of engagement established
   - Safety level configured (Proof-of-Concept mode)

2. Intelligence Gathering
   - Passive reconnaissance
   - Active scanning and enumeration
   - Service identification

3. Vulnerability Analysis
   - Automated vulnerability scanning
   - Manual verification of findings
   - False positive elimination

4. Exploitation (Proof-of-Concept)
   - Vulnerability verification without harm
   - Evidence collection
   - No destructive testing performed

5. Post-Exploitation Analysis
   - Impact assessment
   - Risk rating calculation
   - Remediation prioritization

6. Reporting
   - Finding documentation with evidence
   - Remediation recommendations
   - Executive summary generation

All testing was performed in a controlled manner with safety controls enabled to prevent
any disruption to production systems. Findings were verified through non-destructive
proof-of-concept demonstrations only.`
}

// Export functions

// ToJSON exports report as JSON
func (r *ProfessionalReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToHTML exports report as HTML
func (r *ProfessionalReport) ToHTML() string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + html.EscapeString(r.Title) + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .report { background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; font-size: 28px; }
        .header .meta { color: #666; font-size: 14px; margin-top: 10px; }
        .classification { background: #e74c3c; color: white; padding: 5px 15px; display: inline-block; font-weight: bold; }
        .section { margin: 30px 0; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        .section h3 { color: #34495e; margin: 20px 0 10px; }
        .risk-badge { padding: 8px 16px; border-radius: 4px; color: white; font-weight: bold; display: inline-block; }
        .risk-critical { background: #c0392b; }
        .risk-high { background: #e74c3c; }
        .risk-medium { background: #f39c12; }
        .risk-low { background: #27ae60; }
        .risk-info { background: #3498db; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card .number { font-size: 36px; font-weight: bold; color: #2c3e50; }
        .summary-card .label { color: #666; font-size: 14px; }
        .finding { border: 1px solid #ddd; border-radius: 8px; margin: 15px 0; overflow: hidden; }
        .finding-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .finding-header.critical { background: #fadbd8; border-left: 4px solid #c0392b; }
        .finding-header.high { background: #fdecea; border-left: 4px solid #e74c3c; }
        .finding-header.medium { background: #fef5e7; border-left: 4px solid #f39c12; }
        .finding-header.low { background: #e8f6f3; border-left: 4px solid #27ae60; }
        .finding-body { padding: 20px; background: #fafafa; }
        .finding-body dt { font-weight: bold; margin-top: 10px; color: #2c3e50; }
        .finding-body dd { margin-left: 0; padding: 5px 0; }
        .recommendation { background: #e8f4fc; border-left: 4px solid #3498db; padding: 15px; margin: 10px 0; }
        .timeline { list-style: none; }
        .timeline li { padding: 10px 0; border-left: 2px solid #3498db; padding-left: 20px; margin-left: 10px; position: relative; }
        .timeline li::before { content: ''; width: 12px; height: 12px; background: #3498db; border-radius: 50%; position: absolute; left: -7px; top: 12px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #2c3e50; color: white; }
        tr:hover { background: #f5f5f5; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; text-align: center; }
        @media print { .report { box-shadow: none; } }
    </style>
</head>
<body>
<div class="container">
<div class="report">
`)

	// Header
	sb.WriteString(fmt.Sprintf(`
<div class="header">
    <span class="classification">%s</span>
    <h1>%s</h1>
    <div class="meta">
        <strong>Engagement ID:</strong> %s |
        <strong>Date:</strong> %s |
        <strong>Prepared For:</strong> %s
    </div>
</div>
`, html.EscapeString(r.Classification), html.EscapeString(r.Title),
		html.EscapeString(r.EngagementID), r.ReportDate.Format("January 2, 2006"),
		html.EscapeString(r.CustomerName)))

	// Executive Summary
	if r.ExecutiveSummary != nil {
		riskClass := strings.ToLower(r.ExecutiveSummary.OverallRisk)
		sb.WriteString(fmt.Sprintf(`
<div class="section">
    <h2>Executive Summary</h2>
    <p><strong>Overall Risk Rating:</strong> <span class="risk-badge risk-%s">%s</span> (Score: %d/100)</p>
    <h3>Key Findings</h3>
    <p>%s</p>
    <h3>Business Impact</h3>
    <p>%s</p>
    <h3>Immediate Actions Required</h3>
    <p>%s</p>
</div>
`, riskClass, html.EscapeString(r.ExecutiveSummary.OverallRisk), r.ExecutiveSummary.RiskScore,
			html.EscapeString(r.ExecutiveSummary.KeyFindings),
			html.EscapeString(r.ExecutiveSummary.BusinessImpact),
			html.EscapeString(r.ExecutiveSummary.ImmediateActions)))
	}

	// Findings Summary
	if r.FindingsSummary != nil {
		sb.WriteString(`
<div class="section">
    <h2>Findings Summary</h2>
    <div class="summary-grid">
`)
		for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
			count := r.FindingsSummary.BySeverity[sev]
			sb.WriteString(fmt.Sprintf(`
        <div class="summary-card">
            <div class="number">%d</div>
            <div class="label">%s</div>
        </div>`, count, sev))
		}
		sb.WriteString(`
    </div>
</div>
`)
	}

	// Detailed Findings
	sb.WriteString(`
<div class="section">
    <h2>Detailed Findings</h2>
`)
	for _, f := range r.Findings {
		sevClass := strings.ToLower(f.Severity)
		sb.WriteString(fmt.Sprintf(`
    <div class="finding">
        <div class="finding-header %s">
            <div>
                <strong>%s</strong> - %s
            </div>
            <span class="risk-badge risk-%s">%s</span>
        </div>
        <div class="finding-body">
            <dl>
                <dt>Affected Assets</dt>
                <dd>%s</dd>
                <dt>Description</dt>
                <dd>%s</dd>
                <dt>Impact</dt>
                <dd>%s</dd>
`, sevClass, html.EscapeString(f.ID), html.EscapeString(f.Title),
			sevClass, f.Severity,
			html.EscapeString(strings.Join(f.AffectedAssets, ", ")),
			html.EscapeString(f.Description),
			html.EscapeString(f.Impact)))

		if f.Remediation != nil {
			sb.WriteString(fmt.Sprintf(`
                <dt>Remediation</dt>
                <dd class="recommendation">%s</dd>
`, html.EscapeString(f.Remediation.Remediation)))
		}
		sb.WriteString(`
            </dl>
        </div>
    </div>
`)
	}
	sb.WriteString(`</div>`)

	// Remediation Plan
	if r.RemediationPlan != nil {
		sb.WriteString(`
<div class="section">
    <h2>Remediation Plan</h2>
    <h3>Immediate Priority (24-48 hours)</h3>
    <ul class="timeline">
`)
		for _, item := range r.RemediationPlan.ImmediatePriority {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(item)))
		}
		sb.WriteString(`</ul>
    <h3>Short-Term (1-2 weeks)</h3>
    <ul class="timeline">
`)
		for _, item := range r.RemediationPlan.ShortTerm {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(item)))
		}
		sb.WriteString(`</ul>
</div>
`)
	}

	// Footer
	sb.WriteString(fmt.Sprintf(`
<div class="footer">
    <p>Generated by PentestAI | %s | Safety Level: %s</p>
    <p>This report is confidential and intended for authorized recipients only.</p>
</div>
</div>
</div>
</body>
</html>
`, r.ReportDate.Format("2006-01-02 15:04:05"), r.SafetyLevel))

	return sb.String()
}

// ToMarkdown exports report as Markdown
func (r *ProfessionalReport) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s\n\n", r.Title))
	sb.WriteString(fmt.Sprintf("**Classification:** %s\n\n", r.Classification))
	sb.WriteString(fmt.Sprintf("**Engagement ID:** %s\n", r.EngagementID))
	sb.WriteString(fmt.Sprintf("**Customer:** %s\n", r.CustomerName))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", r.ReportDate.Format("January 2, 2006")))
	sb.WriteString(fmt.Sprintf("**Safety Level:** %s\n\n", r.SafetyLevel))

	sb.WriteString("---\n\n")

	// Executive Summary
	if r.ExecutiveSummary != nil {
		sb.WriteString("## Executive Summary\n\n")
		sb.WriteString(fmt.Sprintf("**Overall Risk:** %s (Score: %d/100)\n\n",
			r.ExecutiveSummary.OverallRisk, r.ExecutiveSummary.RiskScore))
		sb.WriteString(fmt.Sprintf("### Key Findings\n%s\n\n", r.ExecutiveSummary.KeyFindings))
		sb.WriteString(fmt.Sprintf("### Business Impact\n%s\n\n", r.ExecutiveSummary.BusinessImpact))
		sb.WriteString(fmt.Sprintf("### Immediate Actions\n%s\n\n", r.ExecutiveSummary.ImmediateActions))
	}

	// Findings Summary
	if r.FindingsSummary != nil {
		sb.WriteString("## Findings Summary\n\n")
		sb.WriteString("| Severity | Count |\n|----------|-------|\n")
		for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, r.FindingsSummary.BySeverity[sev]))
		}
		sb.WriteString("\n")
	}

	// Detailed Findings
	sb.WriteString("## Detailed Findings\n\n")
	for _, f := range r.Findings {
		sb.WriteString(fmt.Sprintf("### %s: %s\n\n", f.ID, f.Title))
		sb.WriteString(fmt.Sprintf("**Severity:** %s\n\n", f.Severity))
		sb.WriteString(fmt.Sprintf("**Affected:** %s\n\n", strings.Join(f.AffectedAssets, ", ")))
		sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("**Impact:** %s\n\n", f.Impact))

		if f.Remediation != nil {
			sb.WriteString(fmt.Sprintf("**Remediation:**\n%s\n\n", f.Remediation.Remediation))
		}
		sb.WriteString("---\n\n")
	}

	// Remediation Plan
	if r.RemediationPlan != nil {
		sb.WriteString("## Remediation Plan\n\n")
		sb.WriteString("### Immediate (24-48 hours)\n")
		for _, item := range r.RemediationPlan.ImmediatePriority {
			sb.WriteString(fmt.Sprintf("- %s\n", item))
		}
		sb.WriteString("\n### Short-Term (1-2 weeks)\n")
		for _, item := range r.RemediationPlan.ShortTerm {
			sb.WriteString(fmt.Sprintf("- %s\n", item))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// SaveToFile saves the report in the specified format
func (r *ProfessionalReport) SaveToFile(path, format string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	var content []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		content, err = r.ToJSON()
	case "html":
		content = []byte(r.ToHTML())
	case "md", "markdown":
		content = []byte(r.ToMarkdown())
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, content, 0644)
}
