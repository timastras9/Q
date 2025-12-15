package safe

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"pentestai/internal/audit"
	"pentestai/internal/config"
	"pentestai/internal/evidence"
	"pentestai/internal/remediation"
)

// Finding represents a security finding
type Finding struct {
	ID          string                      `json:"id"`
	Type        string                      `json:"type"`
	Title       string                      `json:"title"`
	Severity    string                      `json:"severity"`
	Target      string                      `json:"target"`
	Port        int                         `json:"port,omitempty"`
	Service     string                      `json:"service,omitempty"`
	Description string                      `json:"description"`
	Evidence    []*evidence.Evidence        `json:"evidence,omitempty"`
	Remediation *remediation.Recommendation `json:"remediation,omitempty"`
	CVSS        float64                     `json:"cvss,omitempty"`
	CVE         []string                    `json:"cve,omitempty"`
	VerifiedAt  time.Time                   `json:"verified_at"`
	Metadata    map[string]interface{}      `json:"metadata,omitempty"`
}

// AssessmentResult contains the complete assessment output
type AssessmentResult struct {
	EngagementID    string                 `json:"engagement_id"`
	CustomerName    string                 `json:"customer_name"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	Duration        time.Duration          `json:"duration"`
	Targets         []string               `json:"targets"`
	Scope           []string               `json:"scope"`
	SafetyLevel     string                 `json:"safety_level"`
	Findings        []Finding              `json:"findings"`
	Summary         *AssessmentSummary     `json:"summary"`
	AuditLog        []audit.AuditEvent     `json:"audit_log,omitempty"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AssessmentSummary provides overview statistics
type AssessmentSummary struct {
	TotalFindings    int      `json:"total_findings"`
	CriticalCount    int      `json:"critical_count"`
	HighCount        int      `json:"high_count"`
	MediumCount      int      `json:"medium_count"`
	LowCount         int      `json:"low_count"`
	InfoCount        int      `json:"info_count"`
	HostsScanned     int      `json:"hosts_scanned"`
	PortsDiscovered  int      `json:"ports_discovered"`
	ServicesFound    int      `json:"services_found"`
	CredentialsFound int      `json:"credentials_found"`
	RiskRating       string   `json:"risk_rating"`
	TopVulns         []string `json:"top_vulns"`
}

// SafeCallbacks provides progress updates
type SafeCallbacks struct {
	OnStart          func(target string)
	OnProgress       func(phase string, progress float64, message string)
	OnFinding        func(finding Finding)
	OnComplete       func(result *AssessmentResult)
	OnError          func(err error)
	OnScopeViolation func(target, action string)
}

// SafeRunner wraps the AI runner with safety controls
type SafeRunner struct {
	mu             sync.Mutex
	cfg            *config.Config
	auditLog       *audit.AuditLogger
	evidence       *evidence.EvidenceCollector
	remediationDB  *remediation.Database
	findings       []Finding
	callbacks      SafeCallbacks
	running        bool
	findingCounter int64

	// Stats
	hostsScanned    int
	portsDiscovered int
	servicesFound   int
	credsFound      int
}

// NewSafeRunner creates a new safe assessment runner
func NewSafeRunner(cfg *config.Config) *SafeRunner {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	engagementID := cfg.EngagementID
	if engagementID == "" {
		engagementID = fmt.Sprintf("ENG-%d", time.Now().Unix())
	}

	return &SafeRunner{
		cfg:           cfg,
		auditLog:      audit.GetLogger(),
		evidence:      evidence.NewCollector(cfg.ReportOutputDir, engagementID),
		remediationDB: remediation.NewDatabase(),
		findings:      make([]Finding, 0),
	}
}

// SetCallbacks sets the progress callbacks
func (r *SafeRunner) SetCallbacks(cb SafeCallbacks) {
	r.callbacks = cb
}

// ValidateScope checks if all targets are in scope
func (r *SafeRunner) ValidateScope(targets []string) error {
	if !r.cfg.RequireScope {
		return nil
	}

	if len(r.cfg.AllowedTargets) == 0 {
		return fmt.Errorf("no scope defined - use 'scope add <target>' to define allowed targets")
	}

	for _, target := range targets {
		if !r.cfg.IsInScope(target) {
			return fmt.Errorf("target %s is not in scope", target)
		}
	}

	return nil
}

// AddFinding records a new finding with evidence
func (r *SafeRunner) AddFinding(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.findingCounter++
	f.ID = fmt.Sprintf("FIND-%s-%d", r.cfg.EngagementID, r.findingCounter)
	f.VerifiedAt = time.Now().UTC()

	// Get remediation recommendation
	if f.Remediation == nil {
		f.Remediation = r.remediationDB.Get(f.Type)
	}

	r.findings = append(r.findings, f)

	// Audit log
	r.auditLog.LogVulnerability(f.Target, f.Port, f.Type, f.Description,
		severityToAudit(f.Severity), nil)

	// Callback
	if r.callbacks.OnFinding != nil {
		r.callbacks.OnFinding(f)
	}
}

// CheckScopeAndLog validates scope and logs any violations
func (r *SafeRunner) CheckScopeAndLog(target, action string) bool {
	if !r.cfg.IsInScope(target) {
		r.auditLog.LogScopeViolation(target, action)
		if r.callbacks.OnScopeViolation != nil {
			r.callbacks.OnScopeViolation(target, action)
		}
		return false
	}
	return true
}

// CheckActionAllowed validates if an action is permitted
func (r *SafeRunner) CheckActionAllowed(action string) bool {
	if !r.cfg.IsActionAllowed(action) {
		r.auditLog.LogActionBlocked(action, "",
			fmt.Sprintf("blocked by safety level: %s", r.cfg.SafetyLevel))
		return false
	}
	return true
}

// GetEvidence returns the evidence collector
func (r *SafeRunner) GetEvidence() *evidence.EvidenceCollector {
	return r.evidence
}

// GetAuditLog returns the audit logger
func (r *SafeRunner) GetAuditLog() *audit.AuditLogger {
	return r.auditLog
}

// GetRemediationDB returns the remediation database
func (r *SafeRunner) GetRemediationDB() *remediation.Database {
	return r.remediationDB
}

// GetFindings returns all findings
func (r *SafeRunner) GetFindings() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]Finding, len(r.findings))
	copy(result, r.findings)
	return result
}

// GenerateSummary creates an assessment summary
func (r *SafeRunner) GenerateSummary() *AssessmentSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := &AssessmentSummary{
		TotalFindings:    len(r.findings),
		HostsScanned:     r.hostsScanned,
		PortsDiscovered:  r.portsDiscovered,
		ServicesFound:    r.servicesFound,
		CredentialsFound: r.credsFound,
	}

	vulnTypes := make(map[string]int)

	for _, f := range r.findings {
		vulnTypes[f.Type]++
		switch strings.ToLower(f.Severity) {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		default:
			summary.InfoCount++
		}
	}

	// Determine risk rating
	if summary.CriticalCount > 0 {
		summary.RiskRating = "Critical"
	} else if summary.HighCount > 0 {
		summary.RiskRating = "High"
	} else if summary.MediumCount > 0 {
		summary.RiskRating = "Medium"
	} else if summary.LowCount > 0 {
		summary.RiskRating = "Low"
	} else {
		summary.RiskRating = "Informational"
	}

	// Get top vulnerability types
	for vulnType := range vulnTypes {
		summary.TopVulns = append(summary.TopVulns, vulnType)
	}

	return summary
}

// GenerateResult creates the final assessment result
func (r *SafeRunner) GenerateResult(ctx context.Context, targets []string, startTime time.Time) *AssessmentResult {
	endTime := time.Now()

	result := &AssessmentResult{
		EngagementID: r.cfg.EngagementID,
		CustomerName: r.cfg.CustomerName,
		StartTime:    startTime,
		EndTime:      endTime,
		Duration:     endTime.Sub(startTime),
		Targets:      targets,
		Scope:        r.cfg.AllowedTargets,
		SafetyLevel:  r.cfg.SafetyLevel.String(),
		Findings:     r.GetFindings(),
		Summary:      r.GenerateSummary(),
		Metadata: map[string]interface{}{
			"tester":      r.cfg.TesterName,
			"tool":        "PentestAI",
			"version":     "1.0.0",
			"safety_mode": r.cfg.SafetyLevel.String(),
		},
	}

	// Include audit log if enabled
	if r.cfg.AuditLogging {
		result.AuditLog = r.auditLog.GetEvents()
	}

	// Generate recommendations
	var findingTypes []string
	for _, f := range result.Findings {
		findingTypes = append(findingTypes, f.Type)
	}
	result.Recommendations = generateTopRecommendations(r.remediationDB, findingTypes)

	return result
}

// IncrementStats updates scan statistics
func (r *SafeRunner) IncrementStats(hosts, ports, services, creds int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostsScanned += hosts
	r.portsDiscovered += ports
	r.servicesFound += services
	r.credsFound += creds
}

// Helper functions

func severityToAudit(sev string) audit.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return audit.SeverityCritical
	case "high", "medium":
		return audit.SeverityWarning
	default:
		return audit.SeverityInfo
	}
}

func generateTopRecommendations(db *remediation.Database, findingTypes []string) []string {
	seen := make(map[string]bool)
	var recs []string

	// Priority order: Critical, High, Medium, Low
	priorities := []remediation.Priority{
		remediation.PriorityCritical,
		remediation.PriorityHigh,
		remediation.PriorityMedium,
		remediation.PriorityLow,
	}

	for _, priority := range priorities {
		for _, ft := range findingTypes {
			if seen[ft] {
				continue
			}
			rec := db.Get(ft)
			if rec != nil && rec.Priority == priority {
				seen[ft] = true
				recs = append(recs, fmt.Sprintf("[%s] %s: %s",
					rec.Priority, rec.Title, rec.QuickFix))
			}
		}
	}

	// Limit to top 10
	if len(recs) > 10 {
		recs = recs[:10]
	}

	return recs
}

// SafetyCheck provides a pre-flight check before running
type SafetyCheck struct {
	Passed   bool     `json:"passed"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// PreFlightCheck validates the configuration before running
func (r *SafeRunner) PreFlightCheck(targets []string) *SafetyCheck {
	check := &SafetyCheck{Passed: true}

	// Check scope is defined
	if r.cfg.RequireScope && len(r.cfg.AllowedTargets) == 0 {
		check.Errors = append(check.Errors, "No scope defined - targets must be explicitly allowed")
		check.Passed = false
	}

	// Validate all targets are in scope
	for _, target := range targets {
		if !r.cfg.IsInScope(target) {
			check.Errors = append(check.Errors, fmt.Sprintf("Target %s is not in scope", target))
			check.Passed = false
		}
	}

	// Check safety level
	if r.cfg.SafetyLevel == config.SafetyStandard {
		check.Warnings = append(check.Warnings, "Running in STANDARD mode - some actions may modify target systems")
	}

	// Check audit logging
	if !r.cfg.AuditLogging {
		check.Warnings = append(check.Warnings, "Audit logging is disabled - actions will not be logged")
	}

	// Check engagement info
	if r.cfg.EngagementID == "" {
		check.Warnings = append(check.Warnings, "No engagement ID set - using auto-generated ID")
	}
	if r.cfg.CustomerName == "" {
		check.Warnings = append(check.Warnings, "No customer name set")
	}

	return check
}

// StartAssessment initializes an assessment run
func (r *SafeRunner) StartAssessment(ctx context.Context, targets []string) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("assessment already running")
	}
	r.running = true
	r.mu.Unlock()

	// Pre-flight check
	check := r.PreFlightCheck(targets)
	if !check.Passed {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		return fmt.Errorf("pre-flight check failed: %v", check.Errors)
	}

	// Initialize audit log
	if r.cfg.AuditLogging {
		logPath := r.cfg.AuditLogPath
		if logPath == "" {
			logPath = fmt.Sprintf("./audit-%s.log", r.cfg.EngagementID)
		}
		if err := r.auditLog.Initialize(logPath, r.cfg.EngagementID, r.cfg.TesterName); err != nil {
			return fmt.Errorf("failed to initialize audit log: %w", err)
		}
	}

	// Initialize evidence collection
	if r.cfg.EvidenceCapture {
		if err := r.evidence.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize evidence collector: %w", err)
		}
	}

	// Log start
	r.auditLog.LogScanStart(strings.Join(targets, ", "), r.cfg.AllowedTargets)

	if r.callbacks.OnStart != nil {
		r.callbacks.OnStart(strings.Join(targets, ", "))
	}

	return nil
}

// EndAssessment finalizes the assessment
func (r *SafeRunner) EndAssessment(startTime time.Time) {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()

	duration := time.Since(startTime)
	r.auditLog.LogScanComplete("", len(r.findings), duration)
	r.auditLog.Close()
}
