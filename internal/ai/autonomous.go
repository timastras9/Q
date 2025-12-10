package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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
	}
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
	// Create compact state summary to minimize tokens
	summary := a.compactState(state)

	prompt := fmt.Sprintf(`Pentest AI. Pick next action.

STATE:%s

ACTIONS: scan_ports|service_scan|web_scan|dir_scan|ssh_login|ssh_exec|ftp_anon|redis_check|complete

Reply JSON only:
{"action":"x","target":"ip:port or url","options":{"key":"val"},"reasoning":"brief","risk_level":"low|med|high"}`, summary)

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
		"http_login": true, "redis_check": true, "complete": true,
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
