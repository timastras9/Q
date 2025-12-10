package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pentestai/internal/exploit"
)

// AutoPentester runs autonomous penetration tests guided by AI
type AutoPentester struct {
	client      *ClaudeClient
	maxDepth    int
	maxActions  int
	verbose     bool
	findings    []Finding
	credentials []CredentialFind
	sessions    []SessionInfo
	history     []Action
	exploitDB   *exploit.ExploitDatabase // RAG exploit database
}

type Finding struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Target      string    `json:"target"`
	Port        int       `json:"port,omitempty"`
	Service     string    `json:"service,omitempty"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

type CredentialFind struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash,omitempty"`
	Service  string `json:"service"`
	Target   string `json:"target"`
}

type SessionInfo struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Target   string `json:"target"`
	User     string `json:"user"`
	Platform string `json:"platform"`
}

type Action struct {
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Module    string                 `json:"module,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
	Result    string                 `json:"result"`
	Success   bool                   `json:"success"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

type AIDecision struct {
	Action      string                 `json:"action"`
	Target      string                 `json:"target"`
	Module      string                 `json:"module,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
	Reasoning   string                 `json:"reasoning"`
	Priority    int                    `json:"priority"`
	RiskLevel   string                 `json:"risk_level"`
	NextActions []string               `json:"next_actions,omitempty"`
}

type PentestState struct {
	Target         string           `json:"target"`
	Scope          []string         `json:"scope"`
	Phase          string           `json:"phase"`
	DiscoveredHosts []HostInfo      `json:"discovered_hosts"`
	OpenPorts      []PortInfo       `json:"open_ports"`
	Services       []ServiceInfo    `json:"services"`
	Vulnerabilities []Finding       `json:"vulnerabilities"`
	Credentials    []CredentialFind `json:"credentials"`
	Sessions       []SessionInfo    `json:"sessions"`
	ActionHistory  []Action         `json:"action_history"`
}

type HostInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Status   string `json:"status"`
}

type PortInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
}

type ServiceInfo struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

func NewAutoPentester(client *ClaudeClient) *AutoPentester {
	return &AutoPentester{
		client:     client,
		maxDepth:   5,
		maxActions: 50,
		verbose:    true,
		exploitDB:  exploit.NewExploitDatabase(), // Initialize RAG exploit database
	}
}

// SetExploitDB sets a custom exploit database
func (a *AutoPentester) SetExploitDB(db *exploit.ExploitDatabase) {
	a.exploitDB = db
}

// convertServicesToDiscovery converts ServiceInfo to exploit.ServiceDiscovery for RAG queries
func (a *AutoPentester) convertServicesToDiscovery(services []ServiceInfo) []exploit.ServiceDiscovery {
	var discoveries []exploit.ServiceDiscovery
	for _, svc := range services {
		discoveries = append(discoveries, exploit.ServiceDiscovery{
			Host:    svc.Host,
			Port:    svc.Port,
			Name:    svc.Name,
			Product: svc.Product,
			Version: svc.Version,
			Banner:  svc.Banner,
		})
	}
	return discoveries
}

// getExploitRecommendations queries the RAG exploit database for recommendations
func (a *AutoPentester) getExploitRecommendations(state *PentestState) string {
	if a.exploitDB == nil || len(state.Services) == 0 {
		return ""
	}

	discoveries := a.convertServicesToDiscovery(state.Services)
	recommendations := a.exploitDB.GetRecommendations(discoveries)

	if len(recommendations) == 0 {
		return ""
	}

	// Format recommendations for AI context
	var sb strings.Builder
	sb.WriteString("\n\nEXPLOIT DATABASE RECOMMENDATIONS:\n")

	for i, rec := range recommendations {
		if i >= 5 { // Limit to top 5 recommendations
			break
		}
		sb.WriteString(fmt.Sprintf("- %s (", rec.Exploit.Name))
		if len(rec.Exploit.CVE) > 0 {
			sb.WriteString(strings.Join(rec.Exploit.CVE, ","))
		} else {
			sb.WriteString(rec.Exploit.Type)
		}
		sb.WriteString(fmt.Sprintf(") -> %s:%d [%s] %.0f%% confidence\n",
			rec.Target, rec.Port, rec.Exploit.Severity, rec.Confidence*100))
		if rec.Exploit.Module != "" {
			sb.WriteString(fmt.Sprintf("  Module: %s\n", rec.Exploit.Module))
		}
		if rec.Exploit.Payload != "" {
			sb.WriteString(fmt.Sprintf("  Payload: %s\n", rec.Exploit.Payload))
		}
	}

	return sb.String()
}

func (a *AutoPentester) SetMaxDepth(depth int) {
	a.maxDepth = depth
}

func (a *AutoPentester) SetMaxActions(actions int) {
	a.maxActions = actions
}

func (a *AutoPentester) SetVerbose(v bool) {
	a.verbose = v
}

// compactState creates a minimal token representation of state
func (a *AutoPentester) compactState(state *PentestState) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("T:%s P:%s", state.Target, state.Phase))

	// Compact ports list
	if len(state.OpenPorts) > 0 {
		var ports []string
		for _, p := range state.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d", p.Port))
		}
		// Limit to first 15 ports
		if len(ports) > 15 {
			ports = ports[:15]
		}
		parts = append(parts, fmt.Sprintf("Ports:%s", strings.Join(ports, ",")))
	}

	// Compact services (only name:port)
	if len(state.Services) > 0 {
		var svcs []string
		seen := make(map[string]bool)
		for _, s := range state.Services {
			key := fmt.Sprintf("%s:%d", s.Name, s.Port)
			if !seen[key] && s.Name != "unknown" {
				seen[key] = true
				svc := fmt.Sprintf("%s:%d", s.Name, s.Port)
				if s.Product != "" {
					svc += "(" + s.Product + ")"
				}
				svcs = append(svcs, svc)
			}
		}
		if len(svcs) > 10 {
			svcs = svcs[:10]
		}
		if len(svcs) > 0 {
			parts = append(parts, fmt.Sprintf("Svc:%s", strings.Join(svcs, ",")))
		}
	}

	// Compact vulns (just count by severity)
	if len(state.Vulnerabilities) > 0 {
		counts := make(map[string]int)
		for _, v := range state.Vulnerabilities {
			counts[v.Severity]++
		}
		var vc []string
		for sev, cnt := range counts {
			vc = append(vc, fmt.Sprintf("%s:%d", sev[:1], cnt))
		}
		parts = append(parts, fmt.Sprintf("Vulns:%s", strings.Join(vc, ",")))
	}

	// Credentials found
	if len(state.Credentials) > 0 {
		var creds []string
		for _, c := range state.Credentials {
			creds = append(creds, fmt.Sprintf("%s@%s", c.Username, c.Service))
		}
		parts = append(parts, fmt.Sprintf("Creds:%s", strings.Join(creds, ",")))
	}

	// Last 3 actions only
	if len(state.ActionHistory) > 0 {
		var acts []string
		start := len(state.ActionHistory) - 3
		if start < 0 {
			start = 0
		}
		for _, a := range state.ActionHistory[start:] {
			status := "-"
			if a.Success {
				status = "+"
			}
			acts = append(acts, fmt.Sprintf("%s%s", status, a.Type))
		}
		parts = append(parts, fmt.Sprintf("Last:%s", strings.Join(acts, ",")))
	}

	return strings.Join(parts, " ")
}

// GetNextAction asks AI to decide the next action based on current state
func (a *AutoPentester) GetNextAction(ctx context.Context, state *PentestState) (*AIDecision, error) {
	// Build a set of completed actions to track what's been done
	completedActions := make(map[string]bool)
	sshCredentials := make(map[string]CredentialFind) // Track SSH creds for recon
	sshReuseAttempted := make(map[string]bool)        // Track password reuse attempts

	for _, action := range state.ActionHistory {
		key := fmt.Sprintf("%s:%s", action.Type, action.Target)
		completedActions[key] = true

		// Track password reuse attempts by checking options
		if action.Type == "ssh_login" && action.Options != nil {
			if reuseUser, ok := action.Options["reuse"]; ok {
				reuseKey := fmt.Sprintf("%s:%v", action.Target, reuseUser)
				sshReuseAttempted[reuseKey] = true
			}
		}
	}

	// Track SSH credentials from state
	for _, cred := range state.Credentials {
		if cred.Service == "ssh" {
			sshCredentials[cred.Target] = cred
		}
	}

	// Deterministic exploitation sequence - force these first
	target := state.Target

	// Discover ports dynamically
	sshPorts := []int{}
	httpPorts := []int{}

	for _, p := range state.OpenPorts {
		// Find all SSH ports by common ports or service name
		if p.Port == 22 || p.Port == 222 || p.Port == 2222 || p.Port == 22022 || p.Port == 2022 {
			sshPorts = append(sshPorts, p.Port)
		}
		// Find all HTTP ports by common ports
		if p.Port == 80 || p.Port == 443 || p.Port == 8080 || p.Port == 8081 || p.Port == 8082 || p.Port == 8000 || p.Port == 8443 || p.Port == 3000 || p.Port == 5000 || p.Port == 9000 {
			httpPorts = append(httpPorts, p.Port)
		}
		// Also check by service name for non-standard ports
		for _, svc := range state.Services {
			if svc.Port == p.Port {
				if svc.Name == "ssh" {
					found := false
					for _, sp := range sshPorts {
						if sp == p.Port {
							found = true
							break
						}
					}
					if !found {
						sshPorts = append(sshPorts, p.Port)
					}
				}
				if svc.Name == "http" || svc.Name == "https" || svc.Name == "http-proxy" || svc.Name == "http-alt" {
					found := false
					for _, hp := range httpPorts {
						if hp == p.Port {
							found = true
							break
						}
					}
					if !found {
						httpPorts = append(httpPorts, p.Port)
					}
				}
			}
		}
	}

	// Phase 1: Full port scan if not done
	if !completedActions[fmt.Sprintf("full_scan:%s", target)] && !completedActions[fmt.Sprintf("scan_ports:%s", target)] {
		return &AIDecision{
			Action:    "full_scan",
			Target:    target,
			Reasoning: "Full port scan to discover all services",
			RiskLevel: "low",
		}, nil
	}

	// Phase 2: Web scan all HTTP ports first (discover vulns before exploiting)
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("web_scan:%s", webTarget)] {
			return &AIDecision{
				Action:    "web_scan",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("Web vulnerability scan on port %d", httpPort),
				RiskLevel: "medium",
			}, nil
		}
	}

	// Phase 3: Directory scan all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("dir_scan:%s", webTarget)] {
			return &AIDecision{
				Action:    "dir_scan",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("Directory enumeration on port %d", httpPort),
				RiskLevel: "low",
			}, nil
		}
	}

	// Phase 4: Nuclei CVE scan all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("nuclei_scan:%s", webTarget)] {
			return &AIDecision{
				Action:    "nuclei_scan",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("Nuclei CVE scan on port %d", httpPort),
				RiskLevel: "medium",
			}, nil
		}
	}

	// Phase 4b: Nikto scan all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("nikto_scan:%s", webTarget)] {
			return &AIDecision{
				Action:    "nikto_scan",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("Nikto web scan on port %d", httpPort),
				RiskLevel: "medium",
			}, nil
		}
	}

	// Phase 5: XSS scan all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("xss_scan:%s", webTarget)] {
			return &AIDecision{
				Action:    "xss_scan",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("XSS vulnerability scan on port %d", httpPort),
				RiskLevel: "medium",
			}, nil
		}
	}

	// Phase 6: SQL injection on all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("sqli_exploit:%s", webTarget)] {
			return &AIDecision{
				Action:    "sqli_exploit",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("SQL injection scan on port %d", httpPort),
				RiskLevel: "high",
			}, nil
		}
	}

	// Phase 7: Command injection on all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("cmd_inject:%s", webTarget)] {
			return &AIDecision{
				Action:    "cmd_inject",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("Command injection scan on port %d", httpPort),
				RiskLevel: "high",
			}, nil
		}
	}

	// Phase 8: LFI on all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("lfi_exploit:%s", webTarget)] {
			return &AIDecision{
				Action:    "lfi_exploit",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("Local File Inclusion scan on port %d", httpPort),
				RiskLevel: "high",
			}, nil
		}
	}

	// Phase 9: SSRF on all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("ssrf_exploit:%s", webTarget)] {
			return &AIDecision{
				Action:    "ssrf_exploit",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("SSRF vulnerability scan on port %d", httpPort),
				RiskLevel: "high",
			}, nil
		}
	}

	// Phase 10: File upload on all HTTP ports
	for _, httpPort := range httpPorts {
		webTarget := fmt.Sprintf("http://%s:%d", target, httpPort)
		if !completedActions[fmt.Sprintf("file_upload:%s", webTarget)] {
			return &AIDecision{
				Action:    "file_upload",
				Target:    webTarget,
				Reasoning: fmt.Sprintf("File upload scan on port %d", httpPort),
				RiskLevel: "high",
			}, nil
		}
	}

	// Phase 11: SSH brute force on ALL discovered SSH ports
	for _, sshPort := range sshPorts {
		sshTarget := fmt.Sprintf("%s:%d", target, sshPort)
		if !completedActions[fmt.Sprintf("ssh_login:%s", sshTarget)] {
			return &AIDecision{
				Action:    "ssh_login",
				Target:    sshTarget,
				Reasoning: fmt.Sprintf("SSH brute force on port %d", sshPort),
				RiskLevel: "high",
			}, nil
		}
	}

	// Phase 6: SSH RECON - after successful SSH login, do post-exploitation
	for sshTarget, cred := range sshCredentials {
		reconKey := fmt.Sprintf("ssh_recon:%s", sshTarget)
		if !completedActions[reconKey] {
			return &AIDecision{
				Action:    "ssh_recon",
				Target:    sshTarget,
				Reasoning: fmt.Sprintf("Post-exploitation recon as %s to demonstrate impact", cred.Username),
				RiskLevel: "high",
				Options: map[string]interface{}{
					"username": cred.Username,
					"password": cred.Password,
				},
			}, nil
		}
	}

	// Phase 6b: Try SQLi credentials on SSH (password reuse attack) - LIMIT TO 3 ATTEMPTS
	maxReuseAttempts := 3
	reuseCount := len(sshReuseAttempted)
	if len(sshPorts) > 0 && reuseCount < maxReuseAttempts {
		for _, cred := range state.Credentials {
			if cred.Service == "sqli_dump" && cred.Password != "" {
				for _, sshPort := range sshPorts {
					sshTarget := fmt.Sprintf("%s:%d", target, sshPort)
					reuseKey := fmt.Sprintf("%s:%s", sshTarget, cred.Username)

					if !sshReuseAttempted[reuseKey] && reuseCount < maxReuseAttempts {
						return &AIDecision{
							Action:    "ssh_login",
							Target:    sshTarget,
							Reasoning: fmt.Sprintf("Password reuse attack - trying %s's database password on SSH", cred.Username),
							RiskLevel: "high",
							Options: map[string]interface{}{
								"username": cred.Username,
								"password": cred.Password,
								"reuse":    cred.Username,
							},
						}, nil
					}
				}
			}
		}
	}

	// Phase 15: Credential spraying - try found creds on all services
	if len(state.Credentials) > 0 {
		// Build list of services to spray
		servicePorts := make(map[string]int)
		for _, p := range state.OpenPorts {
			for _, svc := range state.Services {
				if svc.Port == p.Port {
					switch svc.Name {
					case "ftp":
						servicePorts["ftp"] = p.Port
					case "mysql":
						servicePorts["mysql"] = p.Port
					case "redis":
						servicePorts["redis"] = p.Port
					case "http", "http-proxy":
						servicePorts["http"] = p.Port
					}
				}
			}
		}

		// Try each credential on each service
		for _, cred := range state.Credentials {
			if cred.Password == "" {
				continue
			}
			for svcName, port := range servicePorts {
				sprayKey := fmt.Sprintf("cred_spray:%s:%s:%d", cred.Username, svcName, port)
				if !completedActions[sprayKey] {
					return &AIDecision{
						Action:    "cred_spray",
						Target:    fmt.Sprintf("%s:%d", target, port),
						Reasoning: fmt.Sprintf("Credential spray - trying %s on %s:%d", cred.Username, svcName, port),
						RiskLevel: "medium",
						Options: map[string]interface{}{
							"username": cred.Username,
							"password": cred.Password,
							"service":  svcName,
						},
					}, nil
				}
			}
		}
	}

	// If all exploitation done, use AI for additional discovery
	summary := a.compactState(state)

	// Get RAG exploit recommendations for AI context
	exploitRecs := a.getExploitRecommendations(state)

	prompt := fmt.Sprintf(`Pentest AI. EXPLOITATION phase complete. Find additional attack vectors.

STATE:%s
%s
Completed: sqli_exploit, cmd_inject, ssh_login, ssh_recon on main targets.

REMAINING ACTIONS:
- dir_scan: directory enumeration (target=http://ip:port)
- service_scan: banner grab (target=ip:port)
- ftp_anon: check anonymous FTP (target=ip)
- redis_check: check unauthenticated Redis (target=ip)
- lfi_exploit: local file inclusion (target=http://ip:port, uri=/page.php?file=)
- ssrf_exploit: server-side request forgery (target=http://ip:port, uri=/fetch?url=)
- file_upload: malicious file upload (target=http://ip:port, uri=/upload.php)
- nuclei_scan: run Nuclei CVE scanner (target=http://ip:port, templates=cves,critical, severity=critical,high)
- xss_scan: test for XSS vulnerabilities (target=http://ip:port, uri=/search?q=)
- reverse_shell: generate reverse shell payloads (target=ip, lhost=attacker_ip, lport=port)
- subdomain_enum: enumerate subdomains (target=domain.com, timeout=60, threads=10)
- ssl_scan: analyze SSL/TLS config (target=host:port, checks certs, protocols, ciphers)
- complete: all done

Use EXPLOIT DATABASE RECOMMENDATIONS above to prioritize high-confidence exploits.

Reply JSON:
{"action":"x","target":"ip:port","reasoning":"brief","risk_level":"low|med|high"}`, summary, exploitRecs)

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	response, err := a.client.Chat(ctx, messages)
	if err != nil {
		return nil, err
	}

	// Parse JSON from response - handle markdown code blocks
	var decision AIDecision

	// Strip markdown code blocks if present
	response = strings.TrimSpace(response)
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimPrefix(response, "```")
	response = strings.TrimSuffix(response, "```")
	response = strings.TrimSpace(response)

	// Try to extract JSON from response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start != -1 && end != -1 && end > start {
		jsonStr := response[start : end+1]
		if err := json.Unmarshal([]byte(jsonStr), &decision); err != nil {
			// If parsing fails, mark as complete to avoid loops
			decision = AIDecision{
				Action:    "complete",
				Target:    state.Target,
				Reasoning: "Parse error: " + err.Error(),
			}
		}
	} else {
		// No JSON found, mark complete
		decision = AIDecision{
			Action:    "complete",
			Target:    state.Target,
			Reasoning: "No valid JSON in response",
		}
	}

	// Validate action is known
	validActions := map[string]bool{
		"scan_ports": true, "scan_network": true, "service_scan": true,
		"web_scan": true, "dir_scan": true, "ssh_login": true,
		"ssh_exec": true, "ftp_login": true, "ftp_anon": true,
		"http_login": true, "redis_check": true, "cmd_inject": true,
		"sqli_exploit": true, "complete": true, "full_scan": true,
		"ssh_recon": true, "reverse_shell": true, "cred_spray": true,
		"lfi_exploit": true, "ssrf_exploit": true, "file_upload": true,
		"nuclei_scan": true, "xss_scan": true, "nikto_scan": true,
		"subdomain_enum": true, "ssl_scan": true,
	}
	if !validActions[decision.Action] {
		decision.Action = "complete"
		decision.Reasoning = "Unknown action, completing"
	}

	// Detect loops - if last 3 actions are the same, force completion
	if len(state.ActionHistory) >= 3 {
		last3 := state.ActionHistory[len(state.ActionHistory)-3:]
		allSame := true
		for _, a := range last3 {
			if a.Type != decision.Action || a.Target != decision.Target {
				allSame = false
				break
			}
		}
		if allSame {
			decision.Action = "complete"
			decision.Reasoning = "Loop detected, completing"
		}
	}

	return &decision, nil
}

// AnalyzeResults asks AI to analyze scan/exploit results
func (a *AutoPentester) AnalyzeResults(ctx context.Context, action Action, rawOutput string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`Analyze these penetration test results:

ACTION: %s
TARGET: %s
MODULE: %s

OUTPUT:
%s

Identify:
1. Key findings (vulnerabilities, misconfigurations)
2. Credentials discovered
3. Severity levels
4. Recommended next steps
5. Remediation advice

Respond with JSON:
{
  "findings": [{"type": "vuln_type", "severity": "critical/high/medium/low/info", "description": "details", "remediation": "fix"}],
  "credentials": [{"username": "user", "password": "pass", "service": "ssh"}],
  "next_steps": ["step1", "step2"],
  "risk_score": 1-10,
  "summary": "brief summary"
}`, action.Type, action.Target, action.Module, rawOutput)

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	response, err := a.client.Chat(ctx, messages)
	if err != nil {
		return nil, err
	}

	var result AnalysisResult
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start != -1 && end != -1 && end > start {
		json.Unmarshal([]byte(response[start:end+1]), &result)
	}

	return &result, nil
}

type AnalysisResult struct {
	Findings    []Finding        `json:"findings"`
	Credentials []CredentialFind `json:"credentials"`
	NextSteps   []string         `json:"next_steps"`
	RiskScore   int              `json:"risk_score"`
	Summary     string           `json:"summary"`
}

// PlanAttack generates a complete attack plan for a target
func (a *AutoPentester) PlanAttack(ctx context.Context, target string, scope []string, reconData string) (*AttackPlan, error) {
	prompt := fmt.Sprintf(`Create a comprehensive penetration test plan for this target.

TARGET: %s
SCOPE: %s

RECONNAISSANCE DATA:
%s

Create a phased attack plan with:
1. Reconnaissance phase
2. Enumeration phase
3. Vulnerability assessment
4. Exploitation phase
5. Post-exploitation
6. Reporting

For each phase, list specific actions with:
- Action type
- Target
- Expected outcome
- Risk level
- Dependencies (what must complete first)

Respond with JSON:
{
  "target": "target",
  "phases": [
    {
      "name": "Reconnaissance",
      "actions": [
        {"action": "scan_ports", "target": "x", "options": {}, "risk": "low", "depends_on": []}
      ]
    }
  ],
  "estimated_actions": 20,
  "risk_assessment": "overall risk assessment",
  "notes": "important considerations"
}`, target, strings.Join(scope, ", "), reconData)

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	response, err := a.client.Chat(ctx, messages)
	if err != nil {
		return nil, err
	}

	var plan AttackPlan
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start != -1 && end != -1 && end > start {
		json.Unmarshal([]byte(response[start:end+1]), &plan)
	}

	return &plan, nil
}

type AttackPlan struct {
	Target           string  `json:"target"`
	Phases           []Phase `json:"phases"`
	EstimatedActions int     `json:"estimated_actions"`
	RiskAssessment   string  `json:"risk_assessment"`
	Notes            string  `json:"notes"`
}

type Phase struct {
	Name    string        `json:"name"`
	Actions []PlannedAction `json:"actions"`
}

type PlannedAction struct {
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Options   map[string]string `json:"options,omitempty"`
	Risk      string            `json:"risk"`
	DependsOn []int             `json:"depends_on"`
}

// GenerateReport asks AI to create a professional pentest report
func (a *AutoPentester) GenerateReport(ctx context.Context, state *PentestState) (*PentestReport, error) {
	// Count findings
	counts := make(map[string]int)
	for _, v := range state.Vulnerabilities {
		counts[v.Severity]++
	}

	prompt := fmt.Sprintf(`Pentest report for: %s
Findings: crit:%d high:%d med:%d low:%d
Creds found: %d
Services: %d

Write brief JSON:
{"executive_summary":"2 sentences","risk_rating":"Critical|High|Medium|Low","recommendations":["top 3 fixes"],"conclusion":"1 sentence"}`,
		state.Target,
		counts["critical"], counts["high"], counts["medium"], counts["low"],
		len(state.Credentials),
		len(state.Services))

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	response, err := a.client.Chat(ctx, messages)
	if err != nil {
		return nil, err
	}

	var report PentestReport
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start != -1 && end != -1 && end > start {
		json.Unmarshal([]byte(response[start:end+1]), &report)
	}

	// Populate from state data
	report.FindingsSummary = counts
	report.CredentialsFound = state.Credentials
	report.DetailedFindings = state.Vulnerabilities

	return &report, nil
}

type PentestReport struct {
	ExecutiveSummary string            `json:"executive_summary"`
	Scope            string            `json:"scope"`
	Methodology      string            `json:"methodology"`
	RiskRating       string            `json:"risk_rating"`
	FindingsSummary  map[string]int    `json:"findings_summary"`
	DetailedFindings []Finding         `json:"detailed_findings"`
	CredentialsFound []CredentialFind  `json:"credentials_found"`
	Recommendations  []string          `json:"recommendations"`
	Conclusion       string            `json:"conclusion"`
}

// SelectExploitForService asks AI to choose the best exploit for a service
func (a *AutoPentester) SelectExploitForService(ctx context.Context, service ServiceInfo, availableModules []string) (*ExploitRecommendation, error) {
	prompt := fmt.Sprintf(`Select the best exploitation approach for this service:

SERVICE:
  Host: %s
  Port: %d
  Name: %s
  Product: %s
  Version: %s
  Banner: %s

AVAILABLE MODULES:
%s

Consider:
1. Service version vulnerabilities
2. Default credentials
3. Misconfigurations
4. Known CVEs

Respond with JSON:
{
  "recommended_module": "module_path",
  "alternatives": ["other", "modules"],
  "options": {"key": "value"},
  "success_probability": "high/medium/low",
  "reasoning": "why this module",
  "cves": ["CVE-XXXX-XXXX"],
  "preconditions": ["what must be true"]
}`, service.Host, service.Port, service.Name, service.Product, service.Version, service.Banner, strings.Join(availableModules, "\n"))

	messages := []Message{
		{Role: "user", Content: prompt},
	}

	response, err := a.client.Chat(ctx, messages)
	if err != nil {
		return nil, err
	}

	var rec ExploitRecommendation
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start != -1 && end != -1 && end > start {
		json.Unmarshal([]byte(response[start:end+1]), &rec)
	}

	return &rec, nil
}

type ExploitRecommendation struct {
	RecommendedModule  string            `json:"recommended_module"`
	Alternatives       []string          `json:"alternatives"`
	Options            map[string]string `json:"options"`
	SuccessProbability string            `json:"success_probability"`
	Reasoning          string            `json:"reasoning"`
	CVEs               []string          `json:"cves"`
	Preconditions      []string          `json:"preconditions"`
}
