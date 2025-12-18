package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// AIFixer uses LLM to dynamically analyze and fix vulnerabilities
type AIFixer struct {
	client        *ClaudeClient
	containerName string
	outputDir     string
}

// AIFixResult represents the result of AI-driven fix generation
type AIFixResult struct {
	VulnType        string `json:"vuln_type"`
	Target          string `json:"target"`
	Port            int    `json:"port"`
	ContainerName   string `json:"container_name"`
	SourceFile      string `json:"source_file"`
	OriginalCode    string `json:"original_code"`
	FixedCode       string `json:"fixed_code"`
	Explanation     string `json:"explanation"`
	Applied         bool   `json:"applied"`
	Error           string `json:"error,omitempty"`
	ContainerPath   string `json:"container_path,omitempty"`
	RestartRequired bool   `json:"restart_required"`
}

// ServicePathMapping maps ports/services to likely file paths in container
var ServicePathMapping = map[int][]string{
	8086:  {"/app/server.py", "/server.py"},                    // lab-xmlrpc
	8087:  {"/app/server.py", "/server.py"},                    // lab-jsonrpc
	8081:  {"/app/xmlrpc/server.py", "/opt/xmlrpc/server.py"},
	8082:  {"/app/jsonrpc/server.js", "/opt/jsonrpc/server.js"},
	8181:  {"/app/xmlrpc/server.py", "/opt/xmlrpc/server.py"},
	8182:  {"/app/jsonrpc/server.js", "/opt/jsonrpc/server.js"},
	50051: {"/app/server.py", "/server.py"},                    // lab-grpc
	5000:  {"/app/flask/app.py", "/opt/flask/app.py"},
	5001:  {"/app/flask/app.py", "/opt/flask/app.py"},
	3000:  {"/app/node/server.js", "/opt/node/server.js"},
}

// PortToContainer maps ports to container names for the lab setup
var PortToContainer = map[int]string{
	8086:  "lab-xmlrpc",
	8087:  "lab-jsonrpc",
	50051: "lab-grpc",
	3306:  "lab-mysql",
	5432:  "lab-postgres",
	6379:  "lab-redis",
	27017: "lab-mongodb",
	2222:  "lab-ssh",
	21:    "lab-ftp",
}

// VulnTypePathHints maps vulnerability types to service hints
var VulnTypePathHints = map[string][]string{
	"rpc_command_injection":    {"xmlrpc", "jsonrpc", "grpc"},
	"command_injection":        {"flask", "app.py", "server.py"},
	"ssti":                     {"flask", "app.py", "template"},
	"insecure_deserialization": {"flask", "pickle", "yaml"},
	"ssrf":                     {"flask", "fetch", "proxy"},
	"sql_injection":            {"db", "sql", "query"},
	"xxe":                      {"xml", "parse"},
	"path_traversal":           {"file", "read", "path"},
}

// NewAIFixer creates a new AI-driven fixer
func NewAIFixer(containerName, outputDir string) (*AIFixer, error) {
	client, err := NewClaudeClient()
	if err != nil {
		return nil, err
	}

	return &AIFixer{
		client:        client,
		containerName: containerName, // Default container, but will use port mapping
		outputDir:     outputDir,
	}, nil
}

// getContainerForPort returns the container name for a given port
func (af *AIFixer) getContainerForPort(port int) string {
	if container, ok := PortToContainer[port]; ok {
		return container
	}
	return af.containerName // Fallback to default
}

// FindVulnerableFile attempts to locate the vulnerable source file in the container
func (af *AIFixer) FindVulnerableFile(port int, vulnType string) (string, string, string, error) {
	containerName := af.getContainerForPort(port)

	// Try known paths for this port first
	if paths, ok := ServicePathMapping[port]; ok {
		for _, path := range paths {
			content, err := af.readFileFromContainerByName(containerName, path)
			if err == nil && len(content) > 0 {
				return containerName, path, content, nil
			}
		}
	}

	// Use find command to search for relevant files
	searchPatterns := []string{"*.py", "*.js", "server.*", "app.*"}

	for _, pattern := range searchPatterns {
		cmd := exec.Command("docker", "exec", containerName, "find", "/app", "/opt", "/", "-maxdepth", "3", "-name", pattern, "-type", "f")
		output, _ := cmd.Output()

		files := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, file := range files {
			if file == "" || strings.Contains(file, "Permission denied") {
				continue
			}
			content, err := af.readFileFromContainerByName(containerName, file)
			if err == nil && len(content) > 0 {
				// Check if this file contains vulnerability indicators
				if af.containsVulnIndicators(content, vulnType) {
					return containerName, file, content, nil
				}
			}
		}
	}

	return containerName, "", "", fmt.Errorf("could not locate vulnerable file for port %d, vuln %s in container %s", port, vulnType, containerName)
}

// containsVulnIndicators checks if code contains vulnerability patterns
func (af *AIFixer) containsVulnIndicators(code, vulnType string) bool {
	lowerCode := strings.ToLower(code)

	indicators := map[string][]string{
		"command_injection": {"shell=true", "os.system", "subprocess", "exec(", "execsync", "child_process"},
		"rpc_command_injection": {"system.exec", "execute", "shell=true", "subprocess.run"},
		"ssti":                     {"render_template_string", "jinja2", "template"},
		"sql_injection":            {"execute(", "query(", "select * from", "where"},
		"insecure_deserialization": {"pickle.loads", "yaml.load", "marshal.loads"},
		"ssrf":                     {"requests.get", "urllib", "fetch", "http.get"},
		"xxe":                      {"xml.parse", "xmlparser", "etree"},
		"path_traversal":          {"open(", "readfile", "fs.read"},
	}

	vulnLower := strings.ToLower(vulnType)
	for key, patterns := range indicators {
		if strings.Contains(vulnLower, key) {
			for _, pattern := range patterns {
				if strings.Contains(lowerCode, strings.ToLower(pattern)) {
					return true
				}
			}
		}
	}

	// Generic dangerous patterns
	dangerousPatterns := []string{"shell=true", "exec(", "eval(", "system("}
	for _, p := range dangerousPatterns {
		if strings.Contains(lowerCode, p) {
			return true
		}
	}

	return false
}

// readFileFromContainer reads a file from the default Docker container
func (af *AIFixer) readFileFromContainer(path string) (string, error) {
	return af.readFileFromContainerByName(af.containerName, path)
}

// readFileFromContainerByName reads a file from a specific Docker container
func (af *AIFixer) readFileFromContainerByName(containerName, path string) (string, error) {
	cmd := exec.Command("docker", "exec", containerName, "cat", path)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// GenerateAIFix uses LLM to analyze vulnerability and generate a fix
func (af *AIFixer) GenerateAIFix(ctx context.Context, vuln VulnForFix) (*AIFixResult, error) {
	result := &AIFixResult{
		VulnType:      vuln.Type,
		Target:        vuln.Target,
		Port:          vuln.Port,
		ContainerName: af.getContainerForPort(vuln.Port),
	}

	// Try to find the vulnerable source file
	containerName, filePath, sourceCode, err := af.FindVulnerableFile(vuln.Port, vuln.Type)
	if err != nil {
		// Can't find source, generate guidance only
		result.Error = fmt.Sprintf("Could not retrieve source: %v", err)
		guidance, _ := af.generateGuidanceOnly(ctx, vuln)
		result.Explanation = guidance
		return result, nil
	}

	result.ContainerName = containerName
	result.SourceFile = filePath
	result.OriginalCode = sourceCode
	result.ContainerPath = filePath

	// Use AI to analyze and generate fix
	prompt := af.buildFixPrompt(vuln, sourceCode)

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	response, err := af.client.ChatLong(ctx, messages)
	if err != nil {
		result.Error = fmt.Sprintf("AI analysis failed: %v", err)
		return result, nil
	}

	// Parse the AI response
	af.parseAIResponse(response, result)

	return result, nil
}

// VulnForFix represents a vulnerability to be fixed
type VulnForFix struct {
	Type        string `json:"type"`
	Target      string `json:"target"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
}

// buildFixPrompt creates the prompt for AI code fixing
func (af *AIFixer) buildFixPrompt(vuln VulnForFix, sourceCode string) string {
	return fmt.Sprintf(`You are a security remediation expert. Analyze the following vulnerable code and provide a complete, secure version.

VULNERABILITY DETAILS:
- Type: %s
- Service: %s (port %d)
- Severity: %s
- Description: %s
- Evidence: %s

VULNERABLE SOURCE CODE:
%s

REQUIREMENTS:
1. Generate a COMPLETE fixed version of the file (not just the changed parts)
2. Fix ALL security vulnerabilities in the code
3. Maintain functionality while removing dangerous operations
4. Add proper input validation and sanitization
5. Use secure coding patterns (allowlists, parameterized queries, etc.)
6. Add authentication where appropriate
7. Remove or secure any hardcoded secrets

RESPONSE FORMAT:
Return your response as JSON with this exact structure:
{
  "explanation": "Brief explanation of vulnerabilities found and fixes applied",
  "fixed_code": "The complete secured source code",
  "changes_made": ["List of specific changes made"],
  "restart_required": true
}

Important:
- The fixed_code must be complete and runnable
- Do not include markdown code fences in the JSON
- Escape any special characters properly in the JSON string`,
		vuln.Type, vuln.Service, vuln.Port, vuln.Severity, vuln.Description, vuln.Evidence, sourceCode)
}

// generateGuidanceOnly generates fix guidance when source isn't available
func (af *AIFixer) generateGuidanceOnly(ctx context.Context, vuln VulnForFix) (string, error) {
	prompt := fmt.Sprintf(`Provide security remediation guidance for this vulnerability:

Type: %s
Target: %s:%d
Description: %s
Evidence: %s

Provide specific, actionable remediation steps.`, vuln.Type, vuln.Target, vuln.Port, vuln.Description, vuln.Evidence)

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	return af.client.Chat(ctx, messages)
}

// parseAIResponse extracts the fixed code from AI response
func (af *AIFixer) parseAIResponse(response string, result *AIFixResult) {
	// Try to parse as JSON first
	var parsed struct {
		Explanation     string   `json:"explanation"`
		FixedCode       string   `json:"fixed_code"`
		ChangesMade     []string `json:"changes_made"`
		RestartRequired bool     `json:"restart_required"`
	}

	// Clean up response - find JSON
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonStr := response[jsonStart : jsonEnd+1]
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
			result.FixedCode = parsed.FixedCode
			result.Explanation = parsed.Explanation
			if len(parsed.ChangesMade) > 0 {
				result.Explanation += "\n\nChanges made:\n- " + strings.Join(parsed.ChangesMade, "\n- ")
			}
			result.RestartRequired = parsed.RestartRequired
			return
		}
	}

	// Fallback: try to extract code from markdown blocks
	codeRe := regexp.MustCompile("```(?:python|javascript|js|py)?\\s*([\\s\\S]*?)```")
	matches := codeRe.FindAllStringSubmatch(response, -1)
	if len(matches) > 0 {
		// Get the largest code block (likely the full fixed code)
		var largestCode string
		for _, match := range matches {
			if len(match) > 1 && len(match[1]) > len(largestCode) {
				largestCode = match[1]
			}
		}
		result.FixedCode = strings.TrimSpace(largestCode)

		// Extract explanation (text before first code block)
		parts := strings.Split(response, "```")
		if len(parts) > 0 {
			result.Explanation = strings.TrimSpace(parts[0])
		}
		result.RestartRequired = true
		return
	}

	// Last resort: use entire response as explanation
	result.Explanation = response
	result.Error = "Could not extract fixed code from AI response"
}

// ApplyFix copies the fixed code to the container
func (af *AIFixer) ApplyFix(result *AIFixResult) error {
	if result.FixedCode == "" || result.ContainerPath == "" {
		return fmt.Errorf("no fixed code or container path available")
	}

	containerName := result.ContainerName
	if containerName == "" {
		containerName = af.containerName
	}

	// Create a temp file with the fixed code
	tempFile := fmt.Sprintf("/tmp/aifix_%d.tmp", time.Now().UnixNano())
	writeCmd := exec.Command("bash", "-c", fmt.Sprintf("cat > %s", tempFile))
	writeCmd.Stdin = strings.NewReader(result.FixedCode)
	if err := writeCmd.Run(); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Backup original in container
	backupPath := result.ContainerPath + ".vuln.bak"
	backupCmd := exec.Command("docker", "exec", containerName, "cp", result.ContainerPath, backupPath)
	backupCmd.Run() // Ignore errors - backup is optional

	// Copy fixed file to container
	copyCmd := exec.Command("docker", "cp", tempFile, containerName+":"+result.ContainerPath)
	if output, err := copyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy fix to container %s: %w\n%s", containerName, err, string(output))
	}

	// Clean up temp file
	exec.Command("rm", tempFile).Run()

	result.Applied = true
	return nil
}

// RestartContainerService restarts a specific container
func (af *AIFixer) RestartContainerService(containerName string) error {
	cmd := exec.Command("docker", "restart", containerName)
	return cmd.Run()
}

// RestartService restarts services in the container
func (af *AIFixer) RestartService() error {
	// Try supervisorctl first
	cmd := exec.Command("docker", "exec", af.containerName, "supervisorctl", "restart", "all")
	if output, err := cmd.CombinedOutput(); err == nil {
		return nil
	} else {
		// Log but don't fail - supervisorctl might not be available
		_ = output
	}

	// Fallback: restart specific services based on what's running
	services := []string{"xmlrpc", "jsonrpc", "grpc", "flask", "node"}
	for _, svc := range services {
		cmd := exec.Command("docker", "exec", af.containerName, "supervisorctl", "restart", svc)
		cmd.Run() // Ignore errors - service might not exist
	}

	return nil
}

// FixVulnerabilities processes multiple vulnerabilities with AI
func (af *AIFixer) FixVulnerabilities(ctx context.Context, vulns []VulnForFix) ([]*AIFixResult, error) {
	var results []*AIFixResult

	for _, vuln := range vulns {
		fmt.Printf("[AI] Analyzing: %s on port %d\n", vuln.Type, vuln.Port)

		result, err := af.GenerateAIFix(ctx, vuln)
		if err != nil {
			result = &AIFixResult{
				VulnType: vuln.Type,
				Target:   vuln.Target,
				Error:    err.Error(),
			}
		}

		results = append(results, result)
	}

	return results, nil
}
