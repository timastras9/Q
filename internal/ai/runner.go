package ai

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"pentestai/internal/exploit"
	"pentestai/internal/recon"
	"pentestai/internal/webapp"
)

// AutoRunner executes autonomous penetration tests
type AutoRunner struct {
	ai         *AutoPentester
	scanner    *recon.Scanner
	webScanner *webapp.WebScanner
	framework  *exploit.Framework
	state      *PentestState
	callbacks  RunnerCallbacks
	running    bool
	maxActions int
}

type RunnerCallbacks struct {
	OnActionStart  func(action string, target string)
	OnActionEnd    func(action string, success bool, output string)
	OnFinding      func(finding Finding)
	OnCredential   func(cred CredentialFind)
	OnPhaseChange  func(phase string)
	OnComplete     func(report *PentestReport)
	OnError        func(err error)
	OnAIDecision   func(decision *AIDecision)
}

func NewAutoRunner(client *ClaudeClient) *AutoRunner {
	return &AutoRunner{
		ai:         NewAutoPentester(client),
		scanner:    recon.NewScanner(),
		webScanner: webapp.NewWebScanner(),
		framework:  exploit.NewFramework(),
		state: &PentestState{
			Phase: "initialization",
		},
		maxActions: 25, // Default max actions
	}
}

func (r *AutoRunner) SetMaxActions(max int) {
	r.maxActions = max
}

// getOpt safely extracts string option from interface map
func getOpt(opts map[string]interface{}, key string) string {
	if opts == nil {
		return ""
	}
	if v, ok := opts[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return strconv.Itoa(int(val))
		case int:
			return strconv.Itoa(val)
		case bool:
			if val {
				return "true"
			}
			return "false"
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func (r *AutoRunner) SetCallbacks(cb RunnerCallbacks) {
	r.callbacks = cb
}

// Run starts an autonomous pentest against the target
func (r *AutoRunner) Run(ctx context.Context, target string, scope []string) (*PentestReport, error) {
	r.state.Target = target
	r.state.Scope = scope
	r.state.Phase = "reconnaissance"
	r.running = true

	if r.callbacks.OnPhaseChange != nil {
		r.callbacks.OnPhaseChange("reconnaissance")
	}

	actionCount := 0

	for r.running && actionCount < r.maxActions {
		select {
		case <-ctx.Done():
			r.running = false
			break
		default:
		}

		// Get next action from AI
		decision, err := r.ai.GetNextAction(ctx, r.state)
		if err != nil {
			if r.callbacks.OnError != nil {
				r.callbacks.OnError(err)
			}
			continue
		}

		if r.callbacks.OnAIDecision != nil {
			r.callbacks.OnAIDecision(decision)
		}

		// Check for completion
		if decision.Action == "complete" || decision.Action == "report" {
			r.state.Phase = "reporting"
			if r.callbacks.OnPhaseChange != nil {
				r.callbacks.OnPhaseChange("reporting")
			}
			break
		}

		// Execute the action
		if r.callbacks.OnActionStart != nil {
			r.callbacks.OnActionStart(decision.Action, decision.Target)
		}

		action, err := r.executeAction(ctx, decision)
		if err != nil {
			if r.callbacks.OnError != nil {
				r.callbacks.OnError(err)
			}
		}

		if action != nil {
			r.state.ActionHistory = append(r.state.ActionHistory, *action)

			if r.callbacks.OnActionEnd != nil {
				r.callbacks.OnActionEnd(action.Type, action.Success, action.Result)
			}
		}

		actionCount++

		// Update phase based on progress
		r.updatePhase()
	}

	// Generate final report
	report, err := r.ai.GenerateReport(ctx, r.state)
	if err != nil {
		return nil, err
	}

	if r.callbacks.OnComplete != nil {
		r.callbacks.OnComplete(report)
	}

	return report, nil
}

func (r *AutoRunner) Stop() {
	r.running = false
}

func (r *AutoRunner) GetState() *PentestState {
	return r.state
}

func (r *AutoRunner) executeAction(ctx context.Context, decision *AIDecision) (*Action, error) {
	action := &Action{
		Type:      decision.Action,
		Target:    decision.Target,
		Module:    decision.Module,
		Options:   decision.Options,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
	}

	switch decision.Action {
	case "scan_ports":
		return r.actionScanPorts(ctx, action, decision)
	case "scan_network":
		return r.actionScanNetwork(ctx, action, decision)
	case "service_scan":
		return r.actionServiceScan(ctx, action, decision)
	case "web_scan":
		return r.actionWebScan(ctx, action, decision)
	case "dir_scan":
		return r.actionDirScan(ctx, action, decision)
	case "ssh_login":
		return r.actionSSHLogin(ctx, action, decision)
	case "ssh_exec":
		return r.actionSSHExec(ctx, action, decision)
	case "ftp_login":
		return r.actionFTPLogin(ctx, action, decision)
	case "ftp_anon":
		return r.actionFTPAnon(ctx, action, decision)
	case "http_login":
		return r.actionHTTPLogin(ctx, action, decision)
	case "redis_check":
		return r.actionRedisCheck(ctx, action, decision)
	default:
		action.Result = fmt.Sprintf("Unknown action: %s", decision.Action)
		action.Success = false
	}

	return action, nil
}

func (r *AutoRunner) actionScanPorts(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	ports := recon.TopPorts(100)
	if p := getOpt(decision.Options, "ports"); p != "" {
		ports = parsePorts(p)
	}

	opts := recon.ScanOptions{
		Ports:       ports,
		BannerGrab:  true,
		ServiceScan: true,
	}

	host, err := r.scanner.ScanHost(ctx, target, opts)
	if err != nil {
		action.Result = fmt.Sprintf("Scan failed: %v", err)
		action.Success = false
		return action, err
	}

	// Update state with discovered ports
	for _, port := range host.Ports {
		if port.State == "open" {
			r.state.OpenPorts = append(r.state.OpenPorts, PortInfo{
				Host:     target,
				Port:     port.Number,
				Protocol: port.Protocol,
				State:    port.State,
			})

			r.state.Services = append(r.state.Services, ServiceInfo{
				Host:    target,
				Port:    port.Number,
				Name:    port.Service.Name,
				Product: port.Service.Product,
				Version: port.Service.Version,
				Banner:  port.Banner,
			})
		}
	}

	// Add host to discovered hosts
	r.state.DiscoveredHosts = append(r.state.DiscoveredHosts, HostInfo{
		IP:       host.IP,
		Hostname: host.Hostname,
		Status:   host.State,
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Scanned %s - %d open ports found\n", target, len(host.Ports)))
	for _, port := range host.Ports {
		if port.State == "open" {
			sb.WriteString(fmt.Sprintf("  %d/%s - %s", port.Number, port.Protocol, port.Service.Name))
			if port.Service.Product != "" {
				sb.WriteString(fmt.Sprintf(" (%s %s)", port.Service.Product, port.Service.Version))
			}
			sb.WriteString("\n")
		}
	}

	action.Result = sb.String()
	action.Success = len(host.Ports) > 0
	action.Data["host"] = host

	return action, nil
}

func (r *AutoRunner) actionScanNetwork(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	cidr := getOpt(decision.Options, "cidr")
	if cidr == "" {
		cidr = decision.Target
	}

	hosts, err := r.scanner.PingSweep(ctx, cidr)
	if err != nil {
		action.Result = fmt.Sprintf("Network scan failed: %v", err)
		action.Success = false
		return action, err
	}

	for _, ip := range hosts {
		r.state.DiscoveredHosts = append(r.state.DiscoveredHosts, HostInfo{
			IP:     ip,
			Status: "up",
		})
	}

	action.Result = fmt.Sprintf("Discovered %d live hosts: %s", len(hosts), strings.Join(hosts, ", "))
	action.Success = len(hosts) > 0
	action.Data["hosts"] = hosts

	return action, nil
}

func (r *AutoRunner) actionServiceScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	// Parse port from target if format is host:port
	port := 0
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		port, _ = strconv.Atoi(parts[1])
	}
	if port == 0 {
		port, _ = strconv.Atoi(getOpt(decision.Options, "port"))
	}

	opts := recon.ScanOptions{
		Ports:       []int{port},
		BannerGrab:  true,
		ServiceScan: true,
	}

	host, err := r.scanner.ScanHost(ctx, target, opts)
	if err != nil {
		action.Result = fmt.Sprintf("Service scan failed: %v", err)
		action.Success = false
		return action, err
	}

	if len(host.Ports) > 0 {
		p := host.Ports[0]
		action.Result = fmt.Sprintf("Service on %s:%d - %s %s %s\nBanner: %s",
			target, port, p.Service.Name, p.Service.Product, p.Service.Version, p.Banner)
		action.Success = true

		// Update state
		for i, svc := range r.state.Services {
			if svc.Host == target && svc.Port == port {
				r.state.Services[i].Product = p.Service.Product
				r.state.Services[i].Version = p.Service.Version
				r.state.Services[i].Banner = p.Banner
				break
			}
		}
	} else {
		action.Result = "No service information retrieved"
		action.Success = false
	}

	return action, nil
}

func (r *AutoRunner) actionWebScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	url := decision.Target
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	result, err := r.webScanner.Scan(ctx, url)
	if err != nil {
		action.Result = fmt.Sprintf("Web scan failed: %v", err)
		action.Success = false
		return action, err
	}

	// Add findings to state
	for _, finding := range result.Findings {
		f := Finding{
			Type:        finding.Type,
			Severity:    finding.Severity,
			Target:      url,
			Description: finding.Description,
			Evidence:    finding.Evidence,
			Remediation: finding.Remediation,
			Timestamp:   time.Now(),
		}
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, f)

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(f)
		}
	}

	action.Result = result.FormatResult()
	action.Success = true
	action.Data["findings"] = result.Findings
	action.Data["technologies"] = result.Technologies

	return action, nil
}

func (r *AutoRunner) actionDirScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/http/dir_scanner"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse URL to get host and port
	target := decision.Target
	port := "80"
	ssl := "false"

	if strings.HasPrefix(target, "https://") {
		ssl = "true"
		port = "443"
		target = strings.TrimPrefix(target, "https://")
	} else {
		target = strings.TrimPrefix(target, "http://")
	}

	if idx := strings.Index(target, ":"); idx != -1 {
		port = target[idx+1:]
		if slashIdx := strings.Index(port, "/"); slashIdx != -1 {
			port = port[:slashIdx]
		}
		target = target[:idx]
	} else if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)
	module.SetOption("SSL", ssl)

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Dir scan failed: %v", err)
		action.Success = false
		return action, err
	}

	action.Result = result.Output
	action.Success = result.Success
	action.Data["found_paths"] = result.Data["found_paths"]

	return action, nil
}

func (r *AutoRunner) actionSSHLogin(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/ssh/ssh_login"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", decision.Target)

	if port := getOpt(decision.Options, "port"); port != "" {
		module.SetOption("RPORT", port)
	}
	if user := getOpt(decision.Options, "username"); user != "" {
		module.SetOption("USERNAME", user)
	}
	if pass := getOpt(decision.Options, "password"); pass != "" {
		module.SetOption("PASSWORD", pass)
	}
	if userFile := getOpt(decision.Options, "user_file"); userFile != "" {
		module.SetOption("USER_FILE", userFile)
	}
	if passFile := getOpt(decision.Options, "pass_file"); passFile != "" {
		module.SetOption("PASS_FILE", passFile)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("SSH login failed: %v", err)
		action.Success = false
		return action, err
	}

	// Add found credentials to state
	for _, cred := range result.Credentials {
		cf := CredentialFind{
			Username: cred.Username,
			Password: cred.Password,
			Service:  "ssh",
			Target:   decision.Target,
		}
		r.state.Credentials = append(r.state.Credentials, cf)

		if r.callbacks.OnCredential != nil {
			r.callbacks.OnCredential(cf)
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) actionSSHExec(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/ssh/sshexec"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", decision.Target)

	if port := getOpt(decision.Options, "port"); port != "" {
		module.SetOption("RPORT", port)
	}
	if user := getOpt(decision.Options, "username"); user != "" {
		module.SetOption("USERNAME", user)
	}
	if pass := getOpt(decision.Options, "password"); pass != "" {
		module.SetOption("PASSWORD", pass)
	}
	if cmd := getOpt(decision.Options, "cmd"); cmd != "" {
		module.SetOption("CMD", cmd)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("SSH exec failed: %v", err)
		action.Success = false
		return action, err
	}

	action.Result = result.Output
	action.Success = result.Success

	// Add session if successful
	if result.Success {
		r.state.Sessions = append(r.state.Sessions, SessionInfo{
			ID:     fmt.Sprintf("ssh-%d", len(r.state.Sessions)+1),
			Type:   "ssh",
			Target: decision.Target,
			User:   getOpt(decision.Options, "username"),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionFTPLogin(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/ftp/ftp_login"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", decision.Target)

	if port := getOpt(decision.Options, "port"); port != "" {
		module.SetOption("RPORT", port)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("FTP login failed: %v", err)
		action.Success = false
		return action, err
	}

	for _, cred := range result.Credentials {
		cf := CredentialFind{
			Username: cred.Username,
			Password: cred.Password,
			Service:  "ftp",
			Target:   decision.Target,
		}
		r.state.Credentials = append(r.state.Credentials, cf)

		if r.callbacks.OnCredential != nil {
			r.callbacks.OnCredential(cf)
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) actionFTPAnon(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/ftp/anonymous"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", decision.Target)

	if port := getOpt(decision.Options, "port"); port != "" {
		module.SetOption("RPORT", port)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("FTP anon check failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "anonymous_ftp",
			Severity:    "medium",
			Target:      decision.Target,
			Description: "Anonymous FTP access enabled",
			Remediation: "Disable anonymous FTP access",
			Timestamp:   time.Now(),
		})
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) actionHTTPLogin(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/http/http_login"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse URL
	target := decision.Target
	port := "80"
	if strings.HasPrefix(target, "https://") {
		module.SetOption("SSL", "true")
		port = "443"
		target = strings.TrimPrefix(target, "https://")
	} else {
		target = strings.TrimPrefix(target, "http://")
	}

	if idx := strings.Index(target, ":"); idx != -1 {
		port = target[idx+1:]
		target = target[:idx]
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if user := getOpt(decision.Options, "username"); user != "" {
		module.SetOption("USERNAME", user)
	}
	if pass := getOpt(decision.Options, "password"); pass != "" {
		module.SetOption("PASSWORD", pass)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("HTTP login failed: %v", err)
		action.Success = false
		return action, err
	}

	for _, cred := range result.Credentials {
		cf := CredentialFind{
			Username: cred.Username,
			Password: cred.Password,
			Service:  "http",
			Target:   decision.Target,
		}
		r.state.Credentials = append(r.state.Credentials, cf)
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) actionRedisCheck(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/redis/redis_login"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", decision.Target)

	if port := getOpt(decision.Options, "port"); port != "" {
		module.SetOption("RPORT", port)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Redis check failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "redis_unauth",
			Severity:    "critical",
			Target:      decision.Target,
			Description: "Redis accessible without authentication",
			Remediation: "Enable Redis authentication with requirepass",
			Timestamp:   time.Now(),
		})
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) updatePhase() {
	// Determine current phase based on progress
	hasHosts := len(r.state.DiscoveredHosts) > 0
	hasPorts := len(r.state.OpenPorts) > 0
	hasServices := len(r.state.Services) > 0
	hasVulns := len(r.state.Vulnerabilities) > 0
	hasCreds := len(r.state.Credentials) > 0
	hasSessions := len(r.state.Sessions) > 0

	newPhase := r.state.Phase

	if !hasHosts && !hasPorts {
		newPhase = "reconnaissance"
	} else if hasHosts && !hasServices {
		newPhase = "enumeration"
	} else if hasServices && !hasVulns && !hasCreds {
		newPhase = "vulnerability_assessment"
	} else if (hasVulns || hasCreds) && !hasSessions {
		newPhase = "exploitation"
	} else if hasSessions {
		newPhase = "post_exploitation"
	}

	if newPhase != r.state.Phase {
		r.state.Phase = newPhase
		if r.callbacks.OnPhaseChange != nil {
			r.callbacks.OnPhaseChange(newPhase)
		}
	}
}

func parsePorts(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				start, _ := strconv.Atoi(bounds[0])
				end, _ := strconv.Atoi(bounds[1])
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
		} else {
			p, _ := strconv.Atoi(part)
			if p > 0 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
