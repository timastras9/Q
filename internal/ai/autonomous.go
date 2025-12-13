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

	// After port scan, let AI drive all decisions based on findings
	// Build list of completed actions for context
	var completedList []string
	for key := range completedActions {
		completedList = append(completedList, key)
	}
	summary := a.compactState(state)

	// Get RAG exploit recommendations for AI context
	exploitRecs := a.getExploitRecommendations(state)

	prompt := fmt.Sprintf(`You are an expert penetration tester doing a real engagement. Analyze the target and decide what to investigate next.

TARGET STATE:
%s

%s

ALREADY COMPLETED (DO NOT REPEAT THESE):
%s

AVAILABLE ACTIONS:

DATABASE/SERVICE CHECKS - Check these first, often misconfigured!
- redis_check: Check Redis for no-auth access (target=ip) - port 6379
- mongodb_check: Check MongoDB for no-auth (target=ip:27017)
- mysql_check: Check MySQL default creds root/empty (target=ip:3306)
- postgres_check: Check PostgreSQL default creds (target=ip:5432)
- ftp_anon: Check FTP anonymous login (target=ip) - port 21

WEB RECONNAISSANCE
- web_scan: Scan web app for vulnerabilities (target=http://ip:port)
- dir_scan: Find hidden directories/files (target=http://ip:port)
- api_fuzz: Discover API endpoints, test auth bypass (target=http://ip:port)

WEB EXPLOITATION - Try these on interesting web services
- sqli_exploit: SQL injection to extract data (target=http://ip:port)
- cmd_inject: Command injection for RCE (target=http://ip:port)
- lfi_exploit: Local file inclusion (target=http://ip:port)
- xss_scan: Cross-site scripting (target=http://ip:port)

NETWORK SERVICES
- ssh_login: SSH credential brute force (target=ip:port)
- service_scan: Grab service banners (target=ip:port)

POST-EXPLOITATION - After finding credentials
- crack_hash: Crack password hashes (target=hash_value, hash_type=md5)
- ssh_recon: Run commands on compromised SSH (requires username/password options)
- cred_spray: Try found creds on other services (target=ip:port, service=mysql, username=x, password=y)

- complete: Finished - use when you've thoroughly tested everything

STRATEGY:
1. FIRST check databases/services for no-auth (Redis, MongoDB) - these are quick wins
2. Look at each open port and think "what could be vulnerable here?"
3. If you find credentials, try to crack them and reuse them
4. Don't just scan - EXPLOIT what you find
5. Be thorough - a real pentest checks everything

Reply JSON only (pick ONE action):
{"action":"x","target":"ip:port","reasoning":"why this matters","risk_level":"low|med|high"}`, summary, exploitRecs, strings.Join(completedList, ", "))

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
		"subdomain_enum": true, "ssl_scan": true, "api_fuzz": true,
		"crack_hash": true, "mysql_check": true, "mongodb_check": true,
		"postgres_check": true,
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
