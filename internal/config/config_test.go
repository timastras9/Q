package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SafetyLevel != SafetyPoC {
		t.Errorf("Expected SafetyLevel to be SafetyPoC, got %v", cfg.SafetyLevel)
	}

	if !cfg.RequireScope {
		t.Error("Expected RequireScope to be true")
	}

	if !cfg.AuditLogging {
		t.Error("Expected AuditLogging to be true")
	}

	if cfg.MaxCredAttempts != 10 {
		t.Errorf("Expected MaxCredAttempts to be 10, got %d", cfg.MaxCredAttempts)
	}
}

func TestSafetyLevelParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected SafetyLevel
	}{
		{"strict", SafetyStrict},
		{"STRICT", SafetyStrict},
		{"poc", SafetyPoC},
		{"proof-of-concept", SafetyPoC},
		{"standard", SafetyStandard},
		{"invalid", SafetyPoC}, // Default to PoC for invalid input
	}

	for _, tt := range tests {
		result := ParseSafetyLevel(tt.input)
		if result != tt.expected {
			t.Errorf("ParseSafetyLevel(%q) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestScopeManagement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireScope = true

	// Add valid target
	err := cfg.AddToScope("192.168.1.0/24")
	if err != nil {
		t.Errorf("Failed to add valid CIDR: %v", err)
	}

	err = cfg.AddToScope("10.0.0.1")
	if err != nil {
		t.Errorf("Failed to add valid IP: %v", err)
	}

	err = cfg.AddToScope("example.com")
	if err != nil {
		t.Errorf("Failed to add valid hostname: %v", err)
	}

	// Test in-scope check
	if !cfg.IsInScope("192.168.1.50") {
		t.Error("Expected 192.168.1.50 to be in scope (within /24)")
	}

	if !cfg.IsInScope("10.0.0.1") {
		t.Error("Expected 10.0.0.1 to be in scope")
	}

	// Test out-of-scope
	if cfg.IsInScope("172.16.0.1") {
		t.Error("Expected 172.16.0.1 to be out of scope")
	}

	// Clear scope
	cfg.ClearScope()
	if len(cfg.AllowedTargets) != 0 {
		t.Error("Expected scope to be cleared")
	}
}

func TestActionAllowed(t *testing.T) {
	tests := []struct {
		safetyLevel SafetyLevel
		action      string
		expected    bool
	}{
		// Always blocked actions
		{SafetyStandard, "format_disk", false},
		{SafetyPoC, "dos_attack", false},
		{SafetyStrict, "wipe_logs", false},

		// Standard-only actions
		{SafetyStandard, "deploy_backdoor", true},
		{SafetyPoC, "deploy_backdoor", false},
		{SafetyStrict, "deploy_backdoor", false},

		// Strict mode - only detection
		{SafetyStrict, "scan_ports", true},
		{SafetyStrict, "version_detect", true},
		{SafetyStrict, "extract_sample", false},

		// PoC mode - detection and PoC
		{SafetyPoC, "scan_ports", true},
		{SafetyPoC, "version_detect", true},
	}

	for _, tt := range tests {
		cfg := DefaultConfig()
		cfg.SafetyLevel = tt.safetyLevel

		result := cfg.IsActionAllowed(tt.action)
		if result != tt.expected {
			t.Errorf("IsActionAllowed(%v, %q) = %v, expected %v",
				tt.safetyLevel, tt.action, result, tt.expected)
		}
	}
}

func TestPortFiltering(t *testing.T) {
	cfg := DefaultConfig()

	// Default - all ports allowed
	if !cfg.IsPortAllowed(80) {
		t.Error("Expected port 80 to be allowed by default")
	}

	// Exclude specific port
	cfg.ExcludedPorts = []int{22, 3389}
	if cfg.IsPortAllowed(22) {
		t.Error("Expected port 22 to be excluded")
	}
	if !cfg.IsPortAllowed(80) {
		t.Error("Expected port 80 to still be allowed")
	}

	// Allowlist mode
	cfg.ExcludedPorts = []int{}
	cfg.AllowedPorts = []int{80, 443}
	if !cfg.IsPortAllowed(80) {
		t.Error("Expected port 80 to be in allowlist")
	}
	if cfg.IsPortAllowed(22) {
		t.Error("Expected port 22 to be blocked (not in allowlist)")
	}
}

func TestValidTarget(t *testing.T) {
	tests := []struct {
		target   string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.0/8", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"", false},
		{"invalid target!", false},
		{"a b c", false},
	}

	for _, tt := range tests {
		result := isValidTarget(tt.target)
		if result != tt.expected {
			t.Errorf("isValidTarget(%q) = %v, expected %v", tt.target, result, tt.expected)
		}
	}
}
