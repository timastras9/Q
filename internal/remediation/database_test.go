package remediation

import (
	"strings"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	db := NewDatabase()

	if db == nil {
		t.Fatal("Expected non-nil database")
	}

	if len(db.recommendations) == 0 {
		t.Error("Expected recommendations to be loaded")
	}
}

func TestGetRecommendation(t *testing.T) {
	db := NewDatabase()

	tests := []struct {
		vulnType string
		wantNil  bool
	}{
		{"sql_injection", false},
		{"SQL Injection", false},
		{"xss", false},
		{"default_credentials", false},
		{"lfi", false},
		{"nonexistent_vuln_type", true},
	}

	for _, tt := range tests {
		rec := db.Get(tt.vulnType)
		if tt.wantNil && rec != nil {
			t.Errorf("Get(%q) returned recommendation, expected nil", tt.vulnType)
		}
		if !tt.wantNil && rec == nil {
			t.Errorf("Get(%q) returned nil, expected recommendation", tt.vulnType)
		}
	}
}

func TestRecommendationContent(t *testing.T) {
	db := NewDatabase()

	sqli := db.Get("sql_injection")
	if sqli == nil {
		t.Fatal("Expected SQL injection recommendation")
	}

	if sqli.Severity != SeverityCritical {
		t.Errorf("Expected SQLi severity Critical, got %v", sqli.Severity)
	}

	if sqli.Priority != PriorityCritical {
		t.Errorf("Expected SQLi priority Critical, got %v", sqli.Priority)
	}

	if len(sqli.CWE) == 0 || sqli.CWE[0] != "CWE-89" {
		t.Error("Expected CWE-89 for SQL injection")
	}

	if len(sqli.OWASP) == 0 {
		t.Error("Expected OWASP reference for SQL injection")
	}

	if sqli.Remediation == "" {
		t.Error("Expected remediation guidance")
	}

	if len(sqli.CodeExamples) == 0 {
		t.Error("Expected code examples for SQL injection")
	}
}

func TestGetBySeverity(t *testing.T) {
	db := NewDatabase()

	// Get critical and above
	critical := db.GetBySeverity(SeverityCritical)
	if len(critical) == 0 {
		t.Error("Expected at least one critical recommendation")
	}

	for _, rec := range critical {
		if rec.Severity < SeverityCritical {
			t.Errorf("GetBySeverity(Critical) returned %v with severity %v", rec.VulnType, rec.Severity)
		}
	}

	// Get medium and above
	medium := db.GetBySeverity(SeverityMedium)
	if len(medium) < len(critical) {
		t.Error("Expected more results when including medium severity")
	}
}

func TestGenerateRemediationReport(t *testing.T) {
	db := NewDatabase()

	findings := []string{
		"sql_injection",
		"xss",
		"default_credentials",
		"ssl_weak",
	}

	report := db.GenerateRemediationReport(findings)

	if report == "" {
		t.Fatal("Expected non-empty report")
	}

	// Check report contains expected sections
	expectedSections := []string{
		"Remediation Report",
		"Executive Summary",
		"Critical Priority",
		"SQL Injection",
	}

	for _, section := range expectedSections {
		if !strings.Contains(report, section) {
			t.Errorf("Expected report to contain %q", section)
		}
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityInfo, "Informational"},
		{SeverityLow, "Low"},
		{SeverityMedium, "Medium"},
		{SeverityHigh, "High"},
		{SeverityCritical, "Critical"},
	}

	for _, tt := range tests {
		result := tt.severity.String()
		if result != tt.expected {
			t.Errorf("Severity(%d).String() = %q, expected %q", tt.severity, result, tt.expected)
		}
	}
}

func TestPriorityString(t *testing.T) {
	tests := []struct {
		priority Priority
		expected string
	}{
		{PriorityLow, "Low"},
		{PriorityMedium, "Medium"},
		{PriorityHigh, "High"},
		{PriorityCritical, "Critical"},
	}

	for _, tt := range tests {
		result := tt.priority.String()
		if result != tt.expected {
			t.Errorf("Priority(%d).String() = %q, expected %q", tt.priority, result, tt.expected)
		}
	}
}

func TestAllRecommendationsHaveRequiredFields(t *testing.T) {
	db := NewDatabase()

	for _, rec := range db.GetAll() {
		if rec.VulnType == "" {
			t.Error("Found recommendation with empty VulnType")
		}
		if rec.Title == "" {
			t.Errorf("Recommendation %s has empty Title", rec.VulnType)
		}
		if rec.Description == "" {
			t.Errorf("Recommendation %s has empty Description", rec.VulnType)
		}
		if rec.Impact == "" {
			t.Errorf("Recommendation %s has empty Impact", rec.VulnType)
		}
		if rec.Remediation == "" {
			t.Errorf("Recommendation %s has empty Remediation", rec.VulnType)
		}
		if len(rec.References) == 0 {
			t.Errorf("Recommendation %s has no References", rec.VulnType)
		}
		if len(rec.CWE) == 0 {
			t.Errorf("Recommendation %s has no CWE", rec.VulnType)
		}
	}
}
