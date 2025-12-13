package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// SafetyLevel defines how aggressive the testing can be
type SafetyLevel int

const (
	// SafetyStrict - Only detection, no exploitation attempts
	SafetyStrict SafetyLevel = iota
	// SafetyPoC - Proof-of-concept only, verify vulnerability exists without harm
	SafetyPoC
	// SafetyStandard - Standard pentest, may make changes but no destructive actions
	SafetyStandard
)

func (s SafetyLevel) String() string {
	return [...]string{"strict", "poc", "standard"}[s]
}

func ParseSafetyLevel(s string) SafetyLevel {
	switch strings.ToLower(s) {
	case "strict":
		return SafetyStrict
	case "poc", "proof-of-concept":
		return SafetyPoC
	case "standard":
		return SafetyStandard
	default:
		return SafetyPoC // Default to safe PoC mode
	}
}

// Config holds all application configuration
type Config struct {
	mu sync.RWMutex

	// Safety settings
	SafetyLevel     SafetyLevel `json:"safety_level"`
	RequireScope    bool        `json:"require_scope"`     // Must define scope before testing
	AuditLogging    bool        `json:"audit_logging"`     // Log all actions for compliance
	EvidenceCapture bool        `json:"evidence_capture"`  // Capture screenshots/responses

	// Scope enforcement
	AllowedTargets []string `json:"allowed_targets"` // CIDR ranges or hostnames
	ExcludedPorts  []int    `json:"excluded_ports"`  // Never scan these ports
	AllowedPorts   []int    `json:"allowed_ports"`   // Only scan these if set

	// Operational limits
	MaxConcurrency    int `json:"max_concurrency"`
	MaxActionsPerHost int `json:"max_actions_per_host"`
	MaxCredAttempts   int `json:"max_cred_attempts"` // Limit brute force attempts
	TimeoutSeconds    int `json:"timeout_seconds"`

	// AI settings
	MaxAIActions int     `json:"max_ai_actions"`
	MaxAIDepth   int     `json:"max_ai_depth"`
	AIModel      string  `json:"ai_model"`
	MaxAICost    float64 `json:"max_ai_cost"` // Stop if API costs exceed this

	// Paths
	WordlistPath   string `json:"wordlist_path"`
	ReportOutputDir string `json:"report_output_dir"`
	AuditLogPath   string `json:"audit_log_path"`

	// Customer info for reports
	CustomerName    string `json:"customer_name"`
	EngagementID    string `json:"engagement_id"`
	TesterName      string `json:"tester_name"`
	EngagementStart string `json:"engagement_start"`
	EngagementEnd   string `json:"engagement_end"`
}

// DefaultConfig returns a safe default configuration
func DefaultConfig() *Config {
	return &Config{
		SafetyLevel:       SafetyPoC,
		RequireScope:      false, // Allow testing without explicit scope for demos
		AuditLogging:      true,
		EvidenceCapture:   true,
		AllowedTargets:    []string{},
		ExcludedPorts:     []int{},
		AllowedPorts:      []int{},
		MaxConcurrency:    10,
		MaxActionsPerHost: 100,
		MaxCredAttempts:   20, // Allow reasonable credential attempts
		TimeoutSeconds:    30,
		MaxAIActions:      50, // More actions for thorough testing
		MaxAIDepth:        10,
		AIModel:           "claude-sonnet-4-20250514",
		MaxAICost:         10.00,
		WordlistPath:      "/usr/share/wordlists/rockyou.txt",
		ReportOutputDir:   "./reports",
		AuditLogPath:      "./audit.log",
	}
}

// Global config instance
var (
	globalConfig *Config
	configOnce   sync.Once
)

// Get returns the global configuration
func Get() *Config {
	configOnce.Do(func() {
		globalConfig = DefaultConfig()
	})
	return globalConfig
}

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	globalConfig = cfg
	return cfg, nil
}

// SaveToFile saves current configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// SetSafetyLevel updates the safety level
func (c *Config) SetSafetyLevel(level SafetyLevel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SafetyLevel = level
}

// GetSafetyLevel returns current safety level
func (c *Config) GetSafetyLevel() SafetyLevel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SafetyLevel
}

// AddToScope adds a target to the allowed scope
func (c *Config) AddToScope(target string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Validate it's a valid IP, CIDR, or hostname
	if !isValidTarget(target) {
		return fmt.Errorf("invalid target format: %s", target)
	}

	// Check for duplicates
	for _, t := range c.AllowedTargets {
		if t == target {
			return nil // Already in scope
		}
	}

	c.AllowedTargets = append(c.AllowedTargets, target)
	return nil
}

// ClearScope removes all targets from scope
func (c *Config) ClearScope() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AllowedTargets = []string{}
}

// IsInScope checks if a target is within the allowed scope
func (c *Config) IsInScope(target string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.RequireScope || len(c.AllowedTargets) == 0 {
		return true // No scope restriction
	}

	// Parse target IP
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return false
		}
		targetIP = ips[0]
	}

	for _, allowed := range c.AllowedTargets {
		// Check if it's a CIDR range
		if strings.Contains(allowed, "/") {
			_, network, err := net.ParseCIDR(allowed)
			if err == nil && network.Contains(targetIP) {
				return true
			}
		} else {
			// Single IP or hostname
			allowedIP := net.ParseIP(allowed)
			if allowedIP == nil {
				ips, err := net.LookupIP(allowed)
				if err == nil && len(ips) > 0 {
					allowedIP = ips[0]
				}
			}
			if allowedIP != nil && allowedIP.Equal(targetIP) {
				return true
			}
			// Exact hostname match
			if strings.EqualFold(allowed, target) {
				return true
			}
		}
	}

	return false
}

// IsPortAllowed checks if a port can be scanned
func (c *Config) IsPortAllowed(port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check excluded ports first
	for _, p := range c.ExcludedPorts {
		if p == port {
			return false
		}
	}

	// If allowed ports are specified, check against them
	if len(c.AllowedPorts) > 0 {
		for _, p := range c.AllowedPorts {
			if p == port {
				return true
			}
		}
		return false
	}

	return true
}

// IsActionAllowed checks if an action is allowed based on safety level
func (c *Config) IsActionAllowed(action string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Actions that are always blocked
	blockedActions := map[string]bool{
		"format_disk":      true,
		"delete_files":     true,
		"wipe_logs":        true,
		"deploy_ransomware": true,
		"dos_attack":       true,
		"destroy":          true,
	}

	if blockedActions[action] {
		return false
	}

	// Actions allowed only in standard mode (not in PoC or strict)
	standardOnlyActions := map[string]bool{
		"deploy_backdoor":   true,
		"establish_persist": true,
		"modify_config":     true,
		"create_user":       true,
		"escalate_privs":    true,
	}

	if standardOnlyActions[action] && c.SafetyLevel != SafetyStandard {
		return false
	}

	// Actions allowed in PoC mode and above (not in strict)
	pocActions := map[string]bool{
		"extract_sample":   true, // Extract small sample to prove access
		"read_sensitive":   true, // Read but not exfiltrate
		"login_verify":     true, // Verify creds work then logout
		"execute_harmless": true, // Run whoami, id, etc.
	}
	_ = pocActions // Used for documentation of PoC-allowed actions

	if c.SafetyLevel == SafetyStrict {
		// In strict mode, only detection actions are allowed
		detectionActions := map[string]bool{
			"scan_ports":       true,
			"version_detect":   true,
			"vuln_check":       true,
			"banner_grab":      true,
			"ssl_check":        true,
			"web_crawl":        true,
			"dir_enum":         true,
			"service_detect":   true,
		}
		return detectionActions[action]
	}

	return true
}

// Helper to validate target format
func isValidTarget(target string) bool {
	// Check if it's a valid IP
	if net.ParseIP(target) != nil {
		return true
	}

	// Check if it's a valid CIDR
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		return err == nil
	}

	// Check if it looks like a hostname (basic validation)
	if len(target) > 0 && len(target) < 256 {
		// Allow alphanumeric, dots, and hyphens
		for _, c := range target {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '.' || c == '-') {
				return false
			}
		}
		return true
	}

	return false
}

// ProofOfConceptConfig returns settings appropriate for PoC demonstrations
func ProofOfConceptConfig() *Config {
	cfg := DefaultConfig()
	cfg.SafetyLevel = SafetyPoC
	cfg.RequireScope = true
	cfg.AuditLogging = true
	cfg.EvidenceCapture = true
	cfg.MaxCredAttempts = 5      // Very limited cred attempts
	cfg.MaxActionsPerHost = 30   // Limited actions
	return cfg
}

// String returns a human-readable config summary
func (c *Config) String() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("PentestAI Configuration\n")
	sb.WriteString("=======================\n")
	sb.WriteString(fmt.Sprintf("Safety Level:      %s\n", c.SafetyLevel))
	sb.WriteString(fmt.Sprintf("Require Scope:     %v\n", c.RequireScope))
	sb.WriteString(fmt.Sprintf("Audit Logging:     %v\n", c.AuditLogging))
	sb.WriteString(fmt.Sprintf("Evidence Capture:  %v\n", c.EvidenceCapture))
	sb.WriteString(fmt.Sprintf("Max Cred Attempts: %d\n", c.MaxCredAttempts))
	sb.WriteString(fmt.Sprintf("Max AI Actions:    %d\n", c.MaxAIActions))
	sb.WriteString(fmt.Sprintf("Allowed Targets:   %d defined\n", len(c.AllowedTargets)))

	if c.CustomerName != "" {
		sb.WriteString(fmt.Sprintf("\nEngagement: %s (%s)\n", c.CustomerName, c.EngagementID))
	}

	return sb.String()
}
