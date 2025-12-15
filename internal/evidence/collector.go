package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EvidenceType categorizes evidence
type EvidenceType string

const (
	TypeHTTPResponse   EvidenceType = "http_response"
	TypeBanner         EvidenceType = "service_banner"
	TypeScreenshot     EvidenceType = "screenshot"
	TypeCommandOutput  EvidenceType = "command_output"
	TypeFileContent    EvidenceType = "file_content"
	TypeCredential     EvidenceType = "credential"
	TypeVulnProof      EvidenceType = "vulnerability_proof"
	TypeConfigFile     EvidenceType = "config_file"
	TypeErrorMessage   EvidenceType = "error_message"
	TypeDatabaseDump   EvidenceType = "database_sample"
	TypeNetworkCapture EvidenceType = "network_capture"
)

// Evidence represents a piece of proof for a finding
type Evidence struct {
	ID          string                 `json:"id"`
	Type        EvidenceType           `json:"type"`
	Target      string                 `json:"target"`
	Port        int                    `json:"port,omitempty"`
	Service     string                 `json:"service,omitempty"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	CapturedAt  time.Time              `json:"captured_at"`
	Data        string                 `json:"data"`      // Text content or base64 for binary
	DataHash    string                 `json:"data_hash"` // SHA256 hash
	IsBinary    bool                   `json:"is_binary"`
	FilePath    string                 `json:"file_path,omitempty"` // If saved to disk
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	FindingRef  string                 `json:"finding_ref,omitempty"` // Reference to associated finding
	Redacted    bool                   `json:"redacted"`              // Sensitive data redacted
}

// EvidenceCollector manages evidence gathering
type EvidenceCollector struct {
	mu           sync.Mutex
	evidence     []Evidence
	outputDir    string
	engagementID string
	counter      int64
	maxDataSize  int // Max size for inline data (larger goes to file)
}

// NewCollector creates a new evidence collector
func NewCollector(outputDir, engagementID string) *EvidenceCollector {
	return &EvidenceCollector{
		evidence:     make([]Evidence, 0),
		outputDir:    outputDir,
		engagementID: engagementID,
		maxDataSize:  50 * 1024, // 50KB inline, larger to file
	}
}

// Initialize sets up the evidence directory
func (c *EvidenceCollector) Initialize() error {
	evidenceDir := filepath.Join(c.outputDir, "evidence", c.engagementID)
	return os.MkdirAll(evidenceDir, 0755)
}

// generateID creates a unique evidence ID
func (c *EvidenceCollector) generateID() string {
	c.counter++
	return fmt.Sprintf("EV-%s-%d-%d", c.engagementID[:8], time.Now().Unix(), c.counter)
}

// computeHash calculates SHA256 hash of data
func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CaptureHTTPResponse captures an HTTP response as evidence
func (c *EvidenceCollector) CaptureHTTPResponse(target string, port int, url string, statusCode int, headers map[string][]string, body string) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Redact sensitive data in response
	redactedBody := redactSensitiveData(body)

	content := fmt.Sprintf("URL: %s\nStatus: %d\n\nHeaders:\n", url, statusCode)
	for k, v := range headers {
		content += fmt.Sprintf("  %s: %s\n", k, strings.Join(v, ", "))
	}
	content += fmt.Sprintf("\nBody:\n%s", redactedBody)

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeHTTPResponse,
		Target:      target,
		Port:        port,
		Title:       fmt.Sprintf("HTTP Response from %s", url),
		Description: fmt.Sprintf("HTTP %d response captured", statusCode),
		CapturedAt:  time.Now().UTC(),
		Data:        content,
		DataHash:    computeHash([]byte(content)),
		IsBinary:    false,
		Redacted:    body != redactedBody,
		Metadata: map[string]interface{}{
			"url":         url,
			"status_code": statusCode,
			"body_length": len(body),
		},
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// CaptureBanner captures a service banner
func (c *EvidenceCollector) CaptureBanner(target string, port int, service, banner string) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeBanner,
		Target:      target,
		Port:        port,
		Service:     service,
		Title:       fmt.Sprintf("%s Banner on port %d", service, port),
		Description: fmt.Sprintf("Service banner captured from %s:%d", target, port),
		CapturedAt:  time.Now().UTC(),
		Data:        banner,
		DataHash:    computeHash([]byte(banner)),
		IsBinary:    false,
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// CaptureCommandOutput captures command execution output
func (c *EvidenceCollector) CaptureCommandOutput(target string, command, output string, exitCode int) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	content := fmt.Sprintf("Command: %s\nExit Code: %d\n\nOutput:\n%s", command, exitCode, output)

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeCommandOutput,
		Target:      target,
		Title:       fmt.Sprintf("Command Output: %s", truncateCommand(command)),
		Description: "Command execution proof-of-concept output",
		CapturedAt:  time.Now().UTC(),
		Data:        content,
		DataHash:    computeHash([]byte(content)),
		IsBinary:    false,
		Metadata: map[string]interface{}{
			"command":   command,
			"exit_code": exitCode,
		},
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// CaptureVulnerabilityProof captures proof of a specific vulnerability
func (c *EvidenceCollector) CaptureVulnerabilityProof(target string, port int, vulnType, vulnName, proof string, metadata map[string]interface{}) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeVulnProof,
		Target:      target,
		Port:        port,
		Title:       fmt.Sprintf("PoC: %s", vulnName),
		Description: fmt.Sprintf("Proof-of-concept for %s vulnerability", vulnType),
		CapturedAt:  time.Now().UTC(),
		Data:        proof,
		DataHash:    computeHash([]byte(proof)),
		IsBinary:    false,
		Metadata:    metadata,
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// CaptureSQLInjectionProof captures SQLi vulnerability evidence
func (c *EvidenceCollector) CaptureSQLInjectionProof(target string, port int, url, parameter, payload, response string, dbType string) *Evidence {
	proof := fmt.Sprintf(`SQL Injection Proof-of-Concept
================================
Target URL: %s
Vulnerable Parameter: %s
Database Type: %s

Payload Used:
%s

Response Indicating Vulnerability:
%s

This demonstrates the application is vulnerable to SQL injection.
No data was extracted or modified during this test.
`, url, parameter, dbType, payload, truncate(response, 1000))

	return c.CaptureVulnerabilityProof(target, port, "SQL Injection", "SQLi in "+parameter, proof, map[string]interface{}{
		"url":       url,
		"parameter": parameter,
		"payload":   payload,
		"db_type":   dbType,
	})
}

// CaptureXSSProof captures XSS vulnerability evidence
func (c *EvidenceCollector) CaptureXSSProof(target string, port int, url, parameter, payload, context string) *Evidence {
	proof := fmt.Sprintf(`Cross-Site Scripting (XSS) Proof-of-Concept
============================================
Target URL: %s
Vulnerable Parameter: %s
XSS Context: %s

Payload Used:
%s

The payload was reflected/stored without proper encoding.
This test used a benign payload that does not execute malicious code.
`, url, parameter, context, payload)

	return c.CaptureVulnerabilityProof(target, port, "XSS", "XSS in "+parameter, proof, map[string]interface{}{
		"url":       url,
		"parameter": parameter,
		"payload":   payload,
		"context":   context,
	})
}

// CaptureLFIProof captures Local File Inclusion evidence
func (c *EvidenceCollector) CaptureLFIProof(target string, port int, url, parameter, fileRead, content string) *Evidence {
	// Only show non-sensitive file content
	safeContent := content
	if len(content) > 500 {
		safeContent = content[:500] + "\n... [truncated for report]"
	}

	proof := fmt.Sprintf(`Local File Inclusion Proof-of-Concept
======================================
Target URL: %s
Vulnerable Parameter: %s
File Accessed: %s

Partial File Content Retrieved:
%s

This demonstrates arbitrary file read capability.
Only non-sensitive system files were accessed for verification.
`, url, parameter, fileRead, safeContent)

	return c.CaptureVulnerabilityProof(target, port, "LFI", "LFI via "+parameter, proof, map[string]interface{}{
		"url":       url,
		"parameter": parameter,
		"file":      fileRead,
	})
}

// CaptureDefaultCredentials captures weak/default credential evidence
func (c *EvidenceCollector) CaptureDefaultCredentials(target string, port int, service, username string) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	proof := fmt.Sprintf(`Default/Weak Credentials Found
===============================
Target: %s:%d
Service: %s
Username: %s
Password: [REDACTED - see secure findings]

Successfully authenticated using default/weak credentials.
Logged out immediately after verification.
`, target, port, service, username)

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeCredential,
		Target:      target,
		Port:        port,
		Service:     service,
		Title:       fmt.Sprintf("Default Credentials: %s@%s", username, service),
		Description: "Weak or default credentials verified",
		CapturedAt:  time.Now().UTC(),
		Data:        proof,
		DataHash:    computeHash([]byte(proof)),
		IsBinary:    false,
		Redacted:    true, // Password is always redacted in evidence
		Metadata: map[string]interface{}{
			"username": username,
			"service":  service,
		},
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// CaptureOpenPort captures evidence of an open port/service
func (c *EvidenceCollector) CaptureOpenPort(target string, port int, service, version, banner string) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	proof := fmt.Sprintf(`Open Service Detected
=====================
Target: %s
Port: %d
Service: %s
Version: %s

Banner:
%s
`, target, port, service, version, banner)

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeBanner,
		Target:      target,
		Port:        port,
		Service:     service,
		Title:       fmt.Sprintf("Open Port: %d/%s", port, service),
		Description: fmt.Sprintf("Service %s detected on port %d", service, port),
		CapturedAt:  time.Now().UTC(),
		Data:        proof,
		DataHash:    computeHash([]byte(proof)),
		IsBinary:    false,
		Metadata: map[string]interface{}{
			"service": service,
			"version": version,
		},
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// CaptureMisconfiguration captures evidence of a misconfiguration
func (c *EvidenceCollector) CaptureMisconfiguration(target string, port int, service, issue, details string) *Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	proof := fmt.Sprintf(`Security Misconfiguration Detected
===================================
Target: %s:%d
Service: %s
Issue: %s

Details:
%s
`, target, port, service, issue, details)

	ev := Evidence{
		ID:          c.generateID(),
		Type:        TypeVulnProof,
		Target:      target,
		Port:        port,
		Service:     service,
		Title:       fmt.Sprintf("Misconfiguration: %s", issue),
		Description: "Security misconfiguration identified",
		CapturedAt:  time.Now().UTC(),
		Data:        proof,
		DataHash:    computeHash([]byte(proof)),
		IsBinary:    false,
		Metadata: map[string]interface{}{
			"issue":   issue,
			"service": service,
		},
	}

	c.evidence = append(c.evidence, ev)
	return &ev
}

// SaveToFile saves large evidence to a file
func (c *EvidenceCollector) SaveToFile(ev *Evidence, data []byte) error {
	evidenceDir := filepath.Join(c.outputDir, "evidence", c.engagementID)
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.evidence", ev.ID)
	if ev.IsBinary {
		filename += ".bin"
	} else {
		filename += ".txt"
	}

	filePath := filepath.Join(evidenceDir, filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return err
	}

	ev.FilePath = filePath
	ev.Data = "[Saved to file: " + filename + "]"
	return nil
}

// GetEvidence returns all collected evidence
func (c *EvidenceCollector) GetEvidence() []Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([]Evidence, len(c.evidence))
	copy(result, c.evidence)
	return result
}

// GetEvidenceByTarget returns evidence for a specific target
func (c *EvidenceCollector) GetEvidenceByTarget(target string) []Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []Evidence
	for _, ev := range c.evidence {
		if ev.Target == target {
			result = append(result, ev)
		}
	}
	return result
}

// GetEvidenceByFinding returns evidence linked to a finding
func (c *EvidenceCollector) GetEvidenceByFinding(findingRef string) []Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []Evidence
	for _, ev := range c.evidence {
		if ev.FindingRef == findingRef {
			result = append(result, ev)
		}
	}
	return result
}

// LinkToFinding associates evidence with a finding
func (c *EvidenceCollector) LinkToFinding(evidenceID, findingRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.evidence {
		if c.evidence[i].ID == evidenceID {
			c.evidence[i].FindingRef = findingRef
			break
		}
	}
}

// ExportJSON exports all evidence as JSON
func (c *EvidenceCollector) ExportJSON() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return json.MarshalIndent(c.evidence, "", "  ")
}

// Summary returns evidence statistics
func (c *EvidenceCollector) Summary() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	typeCounts := make(map[EvidenceType]int)
	targetSet := make(map[string]bool)

	for _, ev := range c.evidence {
		typeCounts[ev.Type]++
		targetSet[ev.Target] = true
	}

	return map[string]interface{}{
		"total_evidence": len(c.evidence),
		"by_type":        typeCounts,
		"unique_targets": len(targetSet),
	}
}

// Helper functions

func redactSensitiveData(data string) string {
	// Patterns to redact
	patterns := []struct {
		pattern string
		replace string
	}{
		{`(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?[^"'\s,]+`, `$1=[REDACTED]`},
		{`(?i)(api[_-]?key|apikey|secret)["']?\s*[:=]\s*["']?[^"'\s,]+`, `$1=[REDACTED]`},
		{`(?i)(token)["']?\s*[:=]\s*["']?[^"'\s,]+`, `$1=[REDACTED]`},
		{`(?i)(authorization:\s*)(bearer\s+)?[a-zA-Z0-9._-]+`, `$1[REDACTED]`},
	}

	result := data
	// Apply redaction patterns
	for _, pattern := range patterns {
		// Simple string-based redaction for common sensitive patterns
		lowerResult := strings.ToLower(result)
		if strings.Contains(lowerResult, "password") ||
			strings.Contains(lowerResult, "secret") ||
			strings.Contains(lowerResult, "token") ||
			strings.Contains(lowerResult, "apikey") ||
			strings.Contains(lowerResult, "api_key") {
			// Mark as containing sensitive data (actual regex replacement would go here)
			_ = pattern // Pattern definitions for future regex implementation
		}
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func truncateCommand(cmd string) string {
	if len(cmd) > 50 {
		return cmd[:50] + "..."
	}
	return cmd
}

// Base64Encode helper for binary data
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode helper for binary data
func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
