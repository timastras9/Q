package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType categorizes audit events
type EventType string

const (
	EventScanStart      EventType = "scan_start"
	EventScanComplete   EventType = "scan_complete"
	EventTargetAdded    EventType = "target_added"
	EventPortDiscovered EventType = "port_discovered"
	EventServiceFound   EventType = "service_found"
	EventVulnFound      EventType = "vulnerability_found"
	EventCredTested     EventType = "credential_tested"
	EventCredFound      EventType = "credential_found"
	EventExploitCheck   EventType = "exploit_check"
	EventExploitRun     EventType = "exploit_run"
	EventEvidenceCapture EventType = "evidence_captured"
	EventActionBlocked  EventType = "action_blocked"
	EventScopeViolation EventType = "scope_violation"
	EventAIDecision     EventType = "ai_decision"
	EventError          EventType = "error"
	EventReportGenerated EventType = "report_generated"
)

// Severity for audit events
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// AuditEvent represents a single logged event
type AuditEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventID     string                 `json:"event_id"`
	EventType   EventType              `json:"event_type"`
	Severity    Severity               `json:"severity"`
	Target      string                 `json:"target,omitempty"`
	Port        int                    `json:"port,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Module      string                 `json:"module,omitempty"`
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Evidence    *Evidence              `json:"evidence,omitempty"`
	EngagementID string                `json:"engagement_id,omitempty"`
	TesterID    string                 `json:"tester_id,omitempty"`
}

// Evidence captures proof of vulnerability
type Evidence struct {
	Type        string    `json:"type"` // screenshot, response, log, file
	Description string    `json:"description"`
	Data        string    `json:"data,omitempty"`      // Base64 for binary, plain for text
	FilePath    string    `json:"file_path,omitempty"` // If saved to disk
	Hash        string    `json:"hash,omitempty"`      // SHA256 of evidence
	CapturedAt  time.Time `json:"captured_at"`
}

// AuditLogger handles all audit logging
type AuditLogger struct {
	mu           sync.Mutex
	logFile      *os.File
	logPath      string
	engagementID string
	testerID     string
	events       []AuditEvent
	eventCounter int64
	enabled      bool
}

var (
	globalLogger *AuditLogger
	loggerOnce   sync.Once
)

// GetLogger returns the global audit logger
func GetLogger() *AuditLogger {
	loggerOnce.Do(func() {
		globalLogger = &AuditLogger{
			events:  make([]AuditEvent, 0),
			enabled: true,
		}
	})
	return globalLogger
}

// Initialize sets up the audit logger with file output
func (a *AuditLogger) Initialize(logPath, engagementID, testerID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Create directory if needed
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Open log file in append mode
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}

	a.logFile = f
	a.logPath = logPath
	a.engagementID = engagementID
	a.testerID = testerID
	a.enabled = true

	// Log initialization
	a.logInternal(AuditEvent{
		Timestamp:    time.Now().UTC(),
		EventType:    EventScanStart,
		Severity:     SeverityInfo,
		Message:      "Audit logging initialized",
		EngagementID: engagementID,
		TesterID:     testerID,
		Details: map[string]interface{}{
			"log_path": logPath,
		},
	})

	return nil
}

// Close closes the audit log file
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.logFile != nil {
		return a.logFile.Close()
	}
	return nil
}

// SetEnabled enables or disables logging
func (a *AuditLogger) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

// generateEventID creates a unique event ID
func (a *AuditLogger) generateEventID() string {
	a.eventCounter++
	return fmt.Sprintf("%s-%d-%d", a.engagementID, time.Now().UnixNano(), a.eventCounter)
}

// logInternal writes an event (must hold lock)
func (a *AuditLogger) logInternal(event AuditEvent) {
	if !a.enabled {
		return
	}

	if event.EventID == "" {
		event.EventID = a.generateEventID()
	}
	if event.EngagementID == "" {
		event.EngagementID = a.engagementID
	}
	if event.TesterID == "" {
		event.TesterID = a.testerID
	}

	a.events = append(a.events, event)

	// Write to file if available
	if a.logFile != nil {
		data, _ := json.Marshal(event)
		a.logFile.Write(data)
		a.logFile.Write([]byte("\n"))
	}
}

// Log records an audit event
func (a *AuditLogger) Log(event AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	event.Timestamp = time.Now().UTC()
	a.logInternal(event)
}

// LogScanStart records the start of a scan
func (a *AuditLogger) LogScanStart(target string, scope []string) {
	a.Log(AuditEvent{
		EventType: EventScanStart,
		Severity:  SeverityInfo,
		Target:    target,
		Message:   fmt.Sprintf("Scan started against %s", target),
		Details: map[string]interface{}{
			"scope": scope,
		},
	})
}

// LogScanComplete records scan completion
func (a *AuditLogger) LogScanComplete(target string, findings int, duration time.Duration) {
	a.Log(AuditEvent{
		EventType: EventScanComplete,
		Severity:  SeverityInfo,
		Target:    target,
		Success:   true,
		Message:   fmt.Sprintf("Scan completed: %d findings in %s", findings, duration),
		Details: map[string]interface{}{
			"findings_count": findings,
			"duration_ms":    duration.Milliseconds(),
		},
	})
}

// LogVulnerability records a discovered vulnerability
func (a *AuditLogger) LogVulnerability(target string, port int, vulnType, description string, severity Severity, evidence *Evidence) {
	a.Log(AuditEvent{
		EventType: EventVulnFound,
		Severity:  severity,
		Target:    target,
		Port:      port,
		Success:   true,
		Message:   description,
		Evidence:  evidence,
		Details: map[string]interface{}{
			"vulnerability_type": vulnType,
		},
	})
}

// LogCredentialTest records a credential test attempt
func (a *AuditLogger) LogCredentialTest(target string, port int, service, username string, success bool) {
	sev := SeverityInfo
	if success {
		sev = SeverityCritical
	}

	a.Log(AuditEvent{
		EventType: EventCredTested,
		Severity:  sev,
		Target:    target,
		Port:      port,
		Success:   success,
		Message:   fmt.Sprintf("Credential test for %s@%s:%d", username, target, port),
		Details: map[string]interface{}{
			"service":  service,
			"username": username,
			// Note: Never log passwords, even failed ones
		},
	})
}

// LogCredentialFound records discovered credentials
func (a *AuditLogger) LogCredentialFound(target string, service, username, credType string) {
	a.Log(AuditEvent{
		EventType: EventCredFound,
		Severity:  SeverityCritical,
		Target:    target,
		Success:   true,
		Message:   fmt.Sprintf("Valid credentials found: %s@%s (%s)", username, target, service),
		Details: map[string]interface{}{
			"service":         service,
			"username":        username,
			"credential_type": credType,
			// Note: Never log actual passwords
		},
	})
}

// LogExploitCheck records a vulnerability check (without exploitation)
func (a *AuditLogger) LogExploitCheck(target string, port int, module string, vulnerable bool, evidence *Evidence) {
	sev := SeverityInfo
	if vulnerable {
		sev = SeverityCritical
	}

	a.Log(AuditEvent{
		EventType: EventExploitCheck,
		Severity:  sev,
		Target:    target,
		Port:      port,
		Module:    module,
		Success:   vulnerable,
		Message:   fmt.Sprintf("Vulnerability check: %s on %s:%d - %v", module, target, port, vulnerable),
		Evidence:  evidence,
	})
}

// LogExploitRun records an exploitation attempt (PoC)
func (a *AuditLogger) LogExploitRun(target string, port int, module string, success bool, output string, evidence *Evidence) {
	a.Log(AuditEvent{
		EventType: EventExploitRun,
		Severity:  SeverityCritical,
		Target:    target,
		Port:      port,
		Module:    module,
		Success:   success,
		Message:   fmt.Sprintf("Exploit PoC: %s on %s:%d", module, target, port),
		Evidence:  evidence,
		Details: map[string]interface{}{
			"output_preview": truncate(output, 500),
		},
	})
}

// LogActionBlocked records when a safety check prevents an action
func (a *AuditLogger) LogActionBlocked(action, target, reason string) {
	a.Log(AuditEvent{
		EventType: EventActionBlocked,
		Severity:  SeverityWarning,
		Target:    target,
		Action:    action,
		Success:   false,
		Message:   fmt.Sprintf("Action blocked: %s - %s", action, reason),
		Details: map[string]interface{}{
			"reason": reason,
		},
	})
}

// LogScopeViolation records an attempt to access out-of-scope target
func (a *AuditLogger) LogScopeViolation(target, attemptedAction string) {
	a.Log(AuditEvent{
		EventType: EventScopeViolation,
		Severity:  SeverityCritical,
		Target:    target,
		Action:    attemptedAction,
		Success:   false,
		Message:   fmt.Sprintf("SCOPE VIOLATION: Attempted %s on out-of-scope target %s", attemptedAction, target),
	})
}

// LogAIDecision records an AI-made decision
func (a *AuditLogger) LogAIDecision(action, target, reasoning string, riskLevel int) {
	a.Log(AuditEvent{
		EventType: EventAIDecision,
		Severity:  SeverityInfo,
		Target:    target,
		Action:    action,
		Message:   fmt.Sprintf("AI decided: %s on %s", action, target),
		Details: map[string]interface{}{
			"reasoning":  reasoning,
			"risk_level": riskLevel,
		},
	})
}

// LogError records an error
func (a *AuditLogger) LogError(target, action string, err error) {
	a.Log(AuditEvent{
		EventType: EventError,
		Severity:  SeverityWarning,
		Target:    target,
		Action:    action,
		Success:   false,
		Message:   fmt.Sprintf("Error: %v", err),
	})
}

// GetEvents returns all logged events
func (a *AuditLogger) GetEvents() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make([]AuditEvent, len(a.events))
	copy(result, a.events)
	return result
}

// GetEventsByType returns events filtered by type
func (a *AuditLogger) GetEventsByType(eventType EventType) []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	var result []AuditEvent
	for _, e := range a.events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}

// GetVulnerabilities returns all vulnerability findings
func (a *AuditLogger) GetVulnerabilities() []AuditEvent {
	return a.GetEventsByType(EventVulnFound)
}

// GetCredentials returns all credential findings
func (a *AuditLogger) GetCredentials() []AuditEvent {
	return a.GetEventsByType(EventCredFound)
}

// ExportJSON exports all events as JSON
func (a *AuditLogger) ExportJSON() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return json.MarshalIndent(a.events, "", "  ")
}

// Summary returns a summary of the audit log
func (a *AuditLogger) Summary() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()

	typeCounts := make(map[EventType]int)
	severityCounts := make(map[Severity]int)
	targetSet := make(map[string]bool)

	for _, e := range a.events {
		typeCounts[e.EventType]++
		severityCounts[e.Severity]++
		if e.Target != "" {
			targetSet[e.Target] = true
		}
	}

	return map[string]interface{}{
		"total_events":     len(a.events),
		"event_types":      typeCounts,
		"severity_counts":  severityCounts,
		"unique_targets":   len(targetSet),
		"engagement_id":    a.engagementID,
		"vulnerabilities":  typeCounts[EventVulnFound],
		"credentials":      typeCounts[EventCredFound],
		"blocked_actions":  typeCounts[EventActionBlocked],
		"scope_violations": typeCounts[EventScopeViolation],
	}
}

// Helper to truncate strings
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
