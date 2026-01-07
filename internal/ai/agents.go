package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"q/internal/exploit"
	"q/internal/recon"
)

// BaseAgent provides common functionality for all agents
type BaseAgent struct {
	name       string
	agentType  AgentType
	state      *SharedState
	framework  *exploit.Framework
	runner     *AutoRunner // Use the runner for action execution
	maxActions int
	actions    int
	findings   int
	stopped    bool
	callbacks  AgentCallbacks
}

func (b *BaseAgent) Name() string       { return b.name }
func (b *BaseAgent) Type() AgentType    { return b.agentType }
func (b *BaseAgent) Stop()              { b.stopped = true }
func (b *BaseAgent) SetCallbacks(cb AgentCallbacks) { b.callbacks = cb }

func (b *BaseAgent) reportAction(action, target string) {
	if b.callbacks.OnAction != nil {
		b.callbacks.OnAction(b.name, action, target)
	}
}

func (b *BaseAgent) reportFinding(finding Finding) {
	b.findings++
	b.state.AddVulnerability(finding)
	if b.callbacks.OnFinding != nil {
		b.callbacks.OnFinding(b.name, finding)
	}
}

func (b *BaseAgent) reportCredential(cred Credential) {
	b.state.AddCredential(cred)
	if b.callbacks.OnCredential != nil {
		b.callbacks.OnCredential(b.name, cred)
	}
}

func (b *BaseAgent) canContinue() bool {
	return !b.stopped && b.actions < b.maxActions
}

// initRunner initializes the AutoRunner for this agent
func (b *BaseAgent) initRunner(aiClient *ClaudeClient) {
	if aiClient != nil {
		b.runner = NewAutoRunner(aiClient)
		b.runner.state = &PentestState{
			Target: b.state.Target,
			Phase:  "exploitation",
		}
	}
}

// executeAction runs an action using the AutoRunner and processes results
func (b *BaseAgent) executeAction(ctx context.Context, actionType, target string, opts map[string]interface{}) (*Action, error) {
	if b.runner == nil {
		return nil, fmt.Errorf("runner not initialized")
	}

	decision := &AIDecision{
		Action:  actionType,
		Target:  target,
		Options: opts,
	}

	action, err := b.runner.executeAction(ctx, decision)
	if err != nil {
		return nil, err
	}

	// Process findings from runner state
	for _, vuln := range b.runner.state.Vulnerabilities {
		b.reportFinding(vuln)
	}
	// Clear to avoid duplicates
	b.runner.state.Vulnerabilities = nil

	// Process credentials from runner state
	for _, cred := range b.runner.state.Credentials {
		b.reportCredential(Credential{
			Username: cred.Username,
			Password: cred.Password,
			Hash:     cred.Hash,
			Service:  cred.Service,
			Target:   cred.Target,
		})
	}
	// Clear to avoid duplicates
	b.runner.state.Credentials = nil

	return action, nil
}

// =============================================================================
// Recon Agent - Port scanning and service discovery
// =============================================================================

type ReconAgent struct {
	BaseAgent
}

func NewReconAgent(state *SharedState, framework *exploit.Framework, maxActions int) *ReconAgent {
	return &ReconAgent{
		BaseAgent: BaseAgent{
			name:       "recon",
			agentType:  AgentTypeRecon,
			state:      state,
			framework:  framework,
			maxActions: maxActions,
		},
	}
}

func (a *ReconAgent) Run(ctx context.Context) error {
	a.reportAction("full_scan", a.state.Target)
	a.actions++

	// Perform port scan
	scanner := recon.NewScanner()
	host, err := scanner.FastFullScan(ctx, a.state.Target)
	if err != nil {
		return fmt.Errorf("port scan failed: %w", err)
	}

	// Convert results to PortInfo and add to state
	var ports []PortInfo
	for _, p := range host.Ports {
		if p.State == "open" {
			port := PortInfo{
				Host:     a.state.Target,
				Port:     p.Number,
				Protocol: p.Protocol,
				State:    p.State,
			}
			// Store service name in shared state Services map
			if p.Service.Name != "" {
				a.state.Services[p.Number] = p.Service.Name
			}
			ports = append(ports, port)
		}
	}

	// Add all ports and trigger event
	a.state.AddPorts(ports)

	a.reportAction("complete", fmt.Sprintf("%d ports found", len(ports)))
	return nil
}

// =============================================================================
// Web Agent - Web application vulnerability testing
// =============================================================================

type WebAgent struct {
	BaseAgent
	aiClient *ClaudeClient
}

func NewWebAgent(state *SharedState, framework *exploit.Framework, aiClient *ClaudeClient, maxActions int) *WebAgent {
	agent := &WebAgent{
		BaseAgent: BaseAgent{
			name:       "web",
			agentType:  AgentTypeWeb,
			state:      state,
			framework:  framework,
			maxActions: maxActions,
		},
		aiClient: aiClient,
	}
	agent.initRunner(aiClient)
	return agent
}

func (a *WebAgent) Run(ctx context.Context) error {
	// Get web ports to test
	webPorts := []int{}
	for _, p := range a.state.GetPorts() {
		switch p.Port {
		case 80, 443, 8080, 3000, 5000, 8081, 8082, 8083, 8084, 8443:
			webPorts = append(webPorts, p.Port)
		}
	}

	actions := []string{"web_scan", "sqli", "cmd_inject", "lfi_exploit", "dir_bruteforce"}

	for _, port := range webPorts {
		if !a.canContinue() {
			break
		}

		protocol := "http"
		if port == 443 || port == 8443 {
			protocol = "https"
		}
		target := fmt.Sprintf("%s://%s:%d", protocol, a.state.Target, port)

		for _, action := range actions {
			if !a.canContinue() {
				break
			}

			actionKey := fmt.Sprintf("%s:%s", action, target)
			if a.state.IsActionDone(actionKey) {
				continue
			}

			a.reportAction(action, target)
			a.actions++

			result, err := a.executeWebAction(ctx, action, target, port)
			if err != nil {
				a.state.MarkActionFailed(actionKey)
				continue
			}

			a.state.MarkActionComplete(actionKey)
			if result != nil && result.Success {
				// Record findings
				for _, vuln := range result.Vulnerabilities {
					a.reportFinding(Finding{
						Type:        vuln.Type,
						Severity:    vuln.Severity,
						Target:      target,
						Description: vuln.Description,
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return nil
}

func (a *WebAgent) executeWebAction(ctx context.Context, actionType, target string, port int) (*ActionResult, error) {
	result := &ActionResult{Success: false}

	// Use runner's executeAction for actual exploit execution
	opts := map[string]interface{}{
		"port": port,
		"url":  target,
	}

	runnerAction, err := a.executeAction(ctx, actionType, target, opts)
	if err != nil {
		return nil, err
	}

	result.Success = runnerAction.Success
	result.Output = runnerAction.Result

	return result, nil
}

// =============================================================================
// Auth Agent - Authentication and credential testing
// =============================================================================

type AuthAgent struct {
	BaseAgent
	aiClient *ClaudeClient
}

func NewAuthAgent(state *SharedState, framework *exploit.Framework, aiClient *ClaudeClient, maxActions int) *AuthAgent {
	agent := &AuthAgent{
		BaseAgent: BaseAgent{
			name:       "auth",
			agentType:  AgentTypeAuth,
			state:      state,
			framework:  framework,
			maxActions: maxActions,
		},
		aiClient: aiClient,
	}
	agent.initRunner(aiClient)
	return agent
}

func (a *AuthAgent) Run(ctx context.Context) error {
	ports := a.state.GetPorts()

	// Test no-auth services first (Redis, MongoDB)
	for _, p := range ports {
		if !a.canContinue() {
			break
		}

		switch p.Port {
		case 6379:
			a.testRedis(ctx)
		case 27017:
			a.testMongoDB(ctx)
		}
	}

	// Test SSH
	for _, p := range ports {
		if !a.canContinue() {
			break
		}

		if p.Port == 22 || p.Port == 2222 {
			a.testSSH(ctx, p.Port)
		}
	}

	// Test FTP anonymous
	for _, p := range ports {
		if !a.canContinue() {
			break
		}

		if p.Port == 21 {
			a.testFTPAnon(ctx)
		}
	}

	return nil
}

func (a *AuthAgent) testRedis(ctx context.Context) {
	target := fmt.Sprintf("%s:6379", a.state.Target)
	actionKey := "redis_check:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("redis_check", target)
	a.actions++

	// Use runner's action method for actual execution
	action, err := a.executeAction(ctx, "redis_check", target, nil)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	if action != nil && action.Success {
		a.reportFinding(Finding{
			Type:        "redis_unauth",
			Severity:    "critical",
			Target:      target,
			Description: "Redis server accessible without authentication",
			Timestamp:   time.Now(),
		})
	}
}

func (a *AuthAgent) testMongoDB(ctx context.Context) {
	target := fmt.Sprintf("%s:27017", a.state.Target)
	actionKey := "mongodb_check:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("mongodb_check", target)
	a.actions++

	// Use runner's action method for actual execution
	action, err := a.executeAction(ctx, "mongodb_check", target, nil)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	if action != nil && action.Success {
		a.reportFinding(Finding{
			Type:        "mongodb_unauth",
			Severity:    "critical",
			Target:      target,
			Description: "MongoDB accessible without authentication",
			Timestamp:   time.Now(),
		})
	}
}

func (a *AuthAgent) testSSH(ctx context.Context, port int) {
	target := fmt.Sprintf("%s:%d", a.state.Target, port)
	actionKey := "ssh_login:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("ssh_login", target)
	a.actions++

	// Use runner's action method for actual execution
	opts := map[string]interface{}{
		"port": port,
	}
	action, err := a.executeAction(ctx, "ssh_login", target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	// Credentials and findings are already processed by executeAction
	// Check for additional credential data in action result
	if action != nil && action.Success && action.Data != nil {
		if user, ok := action.Data["username"].(string); ok {
			pass, _ := action.Data["password"].(string)
			cred := Credential{
				Username: user,
				Password: pass,
				Service:  fmt.Sprintf("ssh:%d", port),
				Target:   a.state.Target,
			}
			a.reportCredential(cred)
		}

		a.reportFinding(Finding{
			Type:        "ssh_weak_credentials",
			Severity:    "critical",
			Target:      target,
			Description: "SSH server has weak/default credentials",
			Timestamp:   time.Now(),
		})
	}
}

func (a *AuthAgent) testFTPAnon(ctx context.Context) {
	target := fmt.Sprintf("%s:21", a.state.Target)
	actionKey := "ftp_anon:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("ftp_anon", target)
	a.actions++

	// Use runner's action method for actual execution
	action, err := a.executeAction(ctx, "ftp_anon", target, nil)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	if action != nil && action.Success {
		a.reportFinding(Finding{
			Type:        "ftp_anonymous",
			Severity:    "medium",
			Target:      target,
			Description: "FTP server allows anonymous login",
			Timestamp:   time.Now(),
		})
	}
}

// =============================================================================
// RPC Agent - RPC service exploitation
// =============================================================================

type RPCAgent struct {
	BaseAgent
	aiClient *ClaudeClient
}

func NewRPCAgent(state *SharedState, framework *exploit.Framework, aiClient *ClaudeClient, maxActions int) *RPCAgent {
	agent := &RPCAgent{
		BaseAgent: BaseAgent{
			name:       "rpc",
			agentType:  AgentTypeRPC,
			state:      state,
			framework:  framework,
			maxActions: maxActions,
		},
		aiClient: aiClient,
	}
	agent.initRunner(aiClient)
	return agent
}

func (a *RPCAgent) Run(ctx context.Context) error {
	ports := a.state.GetPorts()

	rpcChecks := []struct {
		port   int
		action string
	}{
		{8086, "xmlrpc_exploit"},
		{8087, "jsonrpc_exploit"},
		{50051, "grpc_exploit"},
		{1099, "rmi_exploit"},
		{111, "rpcbind_scan"},
	}

	for _, check := range rpcChecks {
		if !a.canContinue() {
			break
		}

		// Check if port is open
		portOpen := false
		for _, p := range ports {
			if p.Port == check.port {
				portOpen = true
				break
			}
		}

		if !portOpen {
			continue
		}

		target := fmt.Sprintf("%s:%d", a.state.Target, check.port)
		actionKey := check.action + ":" + target

		if a.state.IsActionDone(actionKey) {
			continue
		}

		a.reportAction(check.action, target)
		a.actions++

		// Use runner's executeAction for actual exploitation
		opts := map[string]interface{}{
			"port": check.port,
		}
		result, err := a.executeAction(ctx, check.action, target, opts)
		if err != nil {
			a.state.MarkActionFailed(actionKey)
			continue
		}

		a.state.MarkActionComplete(actionKey)

		// Findings and credentials are processed in executeAction
		// Add additional finding if successful
		if result != nil && result.Success {
			severity := "high"
			if strings.Contains(check.action, "exploit") {
				severity = "critical"
			}

			a.reportFinding(Finding{
				Type:        check.action,
				Severity:    severity,
				Target:      target,
				Description: fmt.Sprintf("RPC vulnerability found via %s", check.action),
				Evidence:    result.Result,
				Timestamp:   time.Now(),
			})
		}
	}

	return nil
}

// =============================================================================
// SSL Agent - SSL/TLS security assessment
// =============================================================================

type SSLAgent struct {
	BaseAgent
	aiClient *ClaudeClient
}

func NewSSLAgent(state *SharedState, framework *exploit.Framework, aiClient *ClaudeClient, maxActions int) *SSLAgent {
	agent := &SSLAgent{
		BaseAgent: BaseAgent{
			name:       "ssl",
			agentType:  AgentTypeSSL,
			state:      state,
			framework:  framework,
			maxActions: maxActions,
		},
		aiClient: aiClient,
	}
	agent.initRunner(aiClient)
	return agent
}

func (a *SSLAgent) Run(ctx context.Context) error {
	ports := a.state.GetPorts()

	sslPorts := []int{}
	for _, p := range ports {
		// Check all common HTTPS ports
		switch p.Port {
		case 443, 8443, 9443, 4443, 8080, 3000:
			// For 8080 and 3000, try SSL anyway - might be HTTPS
			sslPorts = append(sslPorts, p.Port)
		}
	}

	// Also specifically check 8443 even if not in port list (common HTTPS port)
	has8443 := false
	for _, p := range sslPorts {
		if p == 8443 {
			has8443 = true
			break
		}
	}
	if !has8443 {
		sslPorts = append(sslPorts, 8443)
	}

	for _, port := range sslPorts {
		if !a.canContinue() {
			break
		}

		target := fmt.Sprintf("%s:%d", a.state.Target, port)

		// Step 1: SSL vulnerability scan
		a.sslScan(ctx, target, port)

		// Step 2: SSL traffic interception and key capture
		if a.canContinue() {
			a.sslIntercept(ctx, target, port)
		}
	}

	return nil
}

// sslScan performs SSL/TLS vulnerability scanning
func (a *SSLAgent) sslScan(ctx context.Context, target string, port int) {
	actionKey := "ssl_scan:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("ssl_scan", target)
	a.actions++

	// Use runner's executeAction for actual SSL scanning
	opts := map[string]interface{}{
		"port": port,
	}
	result, err := a.executeAction(ctx, "ssl_scan", target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	// Findings are processed in executeAction, but add summary if successful
	if result != nil && result.Success && result.Result != "" {
		a.reportFinding(Finding{
			Type:        "ssl_vulnerabilities",
			Severity:    "medium",
			Target:      target,
			Description: "SSL/TLS vulnerabilities found",
			Evidence:    result.Result,
			Timestamp:   time.Now(),
		})
	}
}

// sslIntercept establishes persistent SSL connection for traffic interception
func (a *SSLAgent) sslIntercept(ctx context.Context, target string, port int) {
	actionKey := "ssl_intercept:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("ssl_intercept", target)
	a.actions++

	// Run SSL interceptor module
	interceptor := exploit.NewSSLInterceptor()
	interceptor.SetOption("RHOSTS", a.state.Target)
	interceptor.SetOption("RPORT", fmt.Sprintf("%d", port))
	interceptor.SetOption("KEYLOG_FILE", fmt.Sprintf("/tmp/sslkeys_%s_%d.log", a.state.Target, port))

	result, err := interceptor.Run(ctx)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	if result != nil && result.Success {
		// Report key extraction
		evidence := result.Output
		if keylogFile, ok := result.Data["keylog_file"].(string); ok {
			evidence += fmt.Sprintf("\nSession keys saved to: %s", keylogFile)
		}

		// Print verbose decrypted traffic directly to console
		if result.Output != "" {
			fmt.Printf("\n%s", result.Output)
		}

		a.reportFinding(Finding{
			Type:        "ssl_intercept",
			Severity:    "info",
			Target:      target,
			Description: "SSL/TLS session keys captured for traffic decryption",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		})

		// Check for sensitive data in captured traffic
		if hasCookies, ok := result.Data["has_cookies"].(bool); ok && hasCookies {
			a.reportFinding(Finding{
				Type:        "session_cookies",
				Severity:    "high",
				Target:      target,
				Description: "Session cookies captured in SSL traffic",
				Evidence:    "Set-Cookie headers found in intercepted response",
				Timestamp:   time.Now(),
			})
		}

		if hasAuth, ok := result.Data["has_auth_headers"].(bool); ok && hasAuth {
			a.reportFinding(Finding{
				Type:        "auth_headers",
				Severity:    "critical",
				Target:      target,
				Description: "Authorization headers captured in SSL traffic",
				Evidence:    "Bearer/Authorization tokens found in intercepted response",
				Timestamp:   time.Now(),
			})
		}

		if hasAPIKeys, ok := result.Data["has_api_keys"].(bool); ok && hasAPIKeys {
			a.reportFinding(Finding{
				Type:        "api_keys",
				Severity:    "critical",
				Target:      target,
				Description: "API keys found in SSL traffic",
				Evidence:    "api_key/apikey patterns found in intercepted response",
				Timestamp:   time.Now(),
			})
		}

		// Extract RSA key info if available
		if rsaMod, ok := result.Data["rsa_modulus"].(string); ok {
			a.reportFinding(Finding{
				Type:        "rsa_key_extracted",
				Severity:    "info",
				Target:      target,
				Description: "RSA public key extracted from certificate",
				Evidence:    fmt.Sprintf("Modulus: %s...", rsaMod[:min(64, len(rsaMod))]),
				Timestamp:   time.Now(),
			})
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// Post-Exploit Agent - Credential spraying, DB enum, hash cracking
// =============================================================================

type PostExploitAgent struct {
	BaseAgent
	aiClient *ClaudeClient
}

func NewPostExploitAgent(state *SharedState, framework *exploit.Framework, aiClient *ClaudeClient, maxActions int) *PostExploitAgent {
	agent := &PostExploitAgent{
		BaseAgent: BaseAgent{
			name:       "post_exploit",
			agentType:  AgentTypePostExploit,
			state:      state,
			framework:  framework,
			maxActions: maxActions,
		},
		aiClient: aiClient,
	}
	agent.initRunner(aiClient)
	return agent
}

func (a *PostExploitAgent) Run(ctx context.Context) error {
	// Step 1: Credential spray to find password reuse
	if a.canContinue() {
		a.credSpray(ctx)
	}

	// Step 2: SSH recon if we have SSH creds
	if a.canContinue() {
		a.sshRecon(ctx)
	}

	// Step 3: Privilege escalation scan via SSH
	if a.canContinue() {
		a.privescScan(ctx)
	}

	// Step 4: SSH pivot to discover internal networks
	if a.canContinue() {
		a.sshPivot(ctx)
	}

	// Step 5: Pivot scan internal hosts
	if a.canContinue() {
		a.pivotScan(ctx)
	}

	// Step 6: Database enumeration
	if a.canContinue() {
		a.dbEnum(ctx)
	}

	// Step 7: Crack any discovered hashes
	if a.canContinue() {
		a.crackHashes(ctx)
	}

	// Step 8: Check Docker registry if port 5000 is open
	if a.canContinue() {
		a.dockerRegistryCheck(ctx)
	}

	return nil
}

func (a *PostExploitAgent) credSpray(ctx context.Context) {
	actionKey := "cred_spray:" + a.state.Target
	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("cred_spray", a.state.Target)
	a.actions++

	creds := a.state.GetCredentials()
	if len(creds) == 0 {
		a.state.MarkActionFailed(actionKey)
		return
	}

	// Get usable credentials
	var usableCreds []Credential
	for _, c := range creds {
		if c.Username != "" && c.Password != "" {
			usableCreds = append(usableCreds, c)
		}
	}

	if len(usableCreds) == 0 {
		a.state.MarkActionFailed(actionKey)
		return
	}

	// Use runner's cred_spray action which handles MySQL, PostgreSQL, etc.
	for _, cred := range usableCreds {
		opts := map[string]interface{}{
			"username": cred.Username,
			"password": cred.Password,
		}
		result, err := a.executeAction(ctx, "cred_spray", a.state.Target, opts)
		if err != nil {
			continue
		}

		// Credentials and findings are processed in executeAction
		if result != nil && result.Success {
			a.reportFinding(Finding{
				Type:        "credential_reuse",
				Severity:    "high",
				Target:      a.state.Target,
				Description: fmt.Sprintf("Password reuse successful with %s credentials", cred.Service),
				Evidence:    result.Result,
				Timestamp:   time.Now(),
			})
		}
	}

	a.state.MarkActionComplete(actionKey)
}

func (a *PostExploitAgent) sshRecon(ctx context.Context) {
	// Check if we have SSH credentials
	var sshCreds []Credential
	var sshPort string = "22" // default SSH port
	for _, c := range a.state.GetCredentials() {
		if strings.HasPrefix(c.Service, "ssh") && c.Username != "" && c.Password != "" {
			sshCreds = append(sshCreds, c)
			// Extract port from service string (format: "ssh:22")
			if parts := strings.Split(c.Service, ":"); len(parts) == 2 {
				sshPort = parts[1]
			}
		}
	}

	if len(sshCreds) == 0 {
		return
	}

	target := fmt.Sprintf("%s:%s", a.state.Target, sshPort)
	actionKey := "ssh_recon:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("ssh_recon", target)
	a.actions++

	// Use runner's ssh_recon action
	opts := map[string]interface{}{
		"port":     sshPort,
		"username": sshCreds[0].Username,
		"password": sshCreds[0].Password,
	}
	result, err := a.executeAction(ctx, "ssh_recon", target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	// Findings are processed in executeAction
	if result != nil && result.Success {
		a.reportFinding(Finding{
			Type:        "ssh_compromise",
			Severity:    "critical",
			Target:      target,
			Description: "SSH shell obtained - post-exploitation recon completed",
			Evidence:    result.Result,
			Timestamp:   time.Now(),
		})
	}
}

func (a *PostExploitAgent) privescScan(ctx context.Context) {
	// Check if we have SSH credentials
	var sshCreds []Credential
	var sshPort string = "22"
	for _, c := range a.state.GetCredentials() {
		if strings.HasPrefix(c.Service, "ssh") && c.Username != "" && c.Password != "" {
			sshCreds = append(sshCreds, c)
			if parts := strings.Split(c.Service, ":"); len(parts) == 2 {
				sshPort = parts[1]
			}
		}
	}

	if len(sshCreds) == 0 {
		return
	}

	target := fmt.Sprintf("%s:%s", a.state.Target, sshPort)
	actionKey := "privesc:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("privesc", target)
	a.actions++

	// Use runner's privesc action for comprehensive privilege escalation scanning
	opts := map[string]interface{}{
		"port":     sshPort,
		"username": sshCreds[0].Username,
		"password": sshCreds[0].Password,
	}
	result, err := a.executeAction(ctx, "privesc", target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	// Findings and credentials are processed in executeAction
	// Report overall privesc success
	if result != nil && result.Success {
		a.reportFinding(Finding{
			Type:        "privilege_escalation_vectors",
			Severity:    "critical",
			Target:      target,
			Description: "Privilege escalation vectors discovered via SSH",
			Evidence:    result.Result,
			Timestamp:   time.Now(),
		})
	}
}

func (a *PostExploitAgent) dbEnum(ctx context.Context) {
	// Check if we have database credentials (check for mysql or postgres in service name)
	var dbCreds []Credential
	for _, c := range a.state.GetCredentials() {
		if (strings.Contains(c.Service, "mysql") || strings.Contains(c.Service, "postgres")) && c.Username != "" && c.Password != "" {
			dbCreds = append(dbCreds, c)
		}
	}

	if len(dbCreds) == 0 {
		return
	}

	actionKey := "db_enum:" + a.state.Target
	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("db_enum", a.state.Target)
	a.actions++

	// Use runner's db_enum action
	opts := map[string]interface{}{
		"username": dbCreds[0].Username,
		"password": dbCreds[0].Password,
	}
	result, err := a.executeAction(ctx, "db_enum", a.state.Target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	// Findings and credentials (including hashes) are processed in executeAction
	if result != nil && result.Success {
		a.reportFinding(Finding{
			Type:        "database_hash_extraction",
			Severity:    "high",
			Target:      a.state.Target,
			Description: "Database enumeration successful - extracted credentials/hashes",
			Evidence:    result.Result,
			Timestamp:   time.Now(),
		})
	}
}

func (a *PostExploitAgent) crackHashes(ctx context.Context) {
	// Get credentials with hashes
	creds := a.state.GetCredentials()

	for _, cred := range creds {
		if !a.canContinue() {
			break
		}

		if cred.Hash == "" {
			continue
		}

		// Check if already cracked
		if _, cracked := a.state.GetCrackedHash(cred.Hash); cracked {
			continue
		}

		actionKey := "crack_hash:" + cred.Hash
		if a.state.IsActionDone(actionKey) {
			continue
		}

		hashDisplay := cred.Hash
		if len(hashDisplay) > 16 {
			hashDisplay = hashDisplay[:16] + "..."
		}
		a.reportAction("crack_hash", hashDisplay)
		a.actions++

		// Use runner's crack_hash action
		opts := map[string]interface{}{
			"hash":     cred.Hash,
			"username": cred.Username,
		}
		result, err := a.executeAction(ctx, "crack_hash", cred.Hash, opts)
		if err != nil {
			a.state.MarkActionFailed(actionKey)
			continue
		}

		a.state.MarkActionComplete(actionKey)

		// Check result for cracked password
		if result != nil && result.Success {
			// Try to get plaintext from action data
			if plaintext, ok := result.Data["plaintext"].(string); ok && plaintext != "" {
				a.state.AddCrackedHash(cred.Hash, plaintext)

				a.reportFinding(Finding{
					Type:        "cracked_password",
					Severity:    "high",
					Target:      hashDisplay,
					Description: "Password hash successfully cracked",
					Timestamp:   time.Now(),
				})

				// Add cracked cred
				crackedCred := Credential{
					Username: cred.Username,
					Password: plaintext,
					Service:  "cracked_hash",
					Target:   cred.Target,
				}
				a.reportCredential(crackedCred)
			}
		}
	}
}

func (a *PostExploitAgent) sshPivot(ctx context.Context) {
	// Check if we have SSH credentials
	var sshCreds []Credential
	var sshPort string = "22"
	for _, c := range a.state.GetCredentials() {
		if strings.HasPrefix(c.Service, "ssh") && c.Username != "" && c.Password != "" {
			sshCreds = append(sshCreds, c)
			if parts := strings.Split(c.Service, ":"); len(parts) == 2 {
				sshPort = parts[1]
			}
		}
	}

	if len(sshCreds) == 0 {
		return
	}

	target := fmt.Sprintf("%s:%s", a.state.Target, sshPort)
	actionKey := "ssh_pivot:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("ssh_pivot", target)
	a.actions++

	// Use runner's ssh_pivot action
	opts := map[string]interface{}{
		"port":     sshPort,
		"username": sshCreds[0].Username,
		"password": sshCreds[0].Password,
	}
	result, err := a.executeAction(ctx, "ssh_pivot", target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	if result != nil && result.Success {
		a.reportFinding(Finding{
			Type:        "internal_network_discovery",
			Severity:    "high",
			Target:      target,
			Description: "Pivot scan discovered internal network hosts via SSH",
			Evidence:    result.Result,
			Timestamp:   time.Now(),
		})
	}
}

func (a *PostExploitAgent) pivotScan(ctx context.Context) {
	// Check if we have SSH credentials
	var sshCreds []Credential
	for _, c := range a.state.GetCredentials() {
		if strings.HasPrefix(c.Service, "ssh") && c.Username != "" && c.Password != "" {
			sshCreds = append(sshCreds, c)
		}
	}

	if len(sshCreds) == 0 {
		return
	}

	actionKey := "pivot_scan:" + a.state.Target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("pivot_scan", a.state.Target)
	a.actions++

	// Use runner's pivot_scan action
	opts := map[string]interface{}{
		"username": sshCreds[0].Username,
		"password": sshCreds[0].Password,
	}
	result, err := a.executeAction(ctx, "pivot_scan", a.state.Target, opts)
	if err != nil {
		a.state.MarkActionFailed(actionKey)
		return
	}

	a.state.MarkActionComplete(actionKey)

	if result != nil && result.Success {
		a.reportFinding(Finding{
			Type:        "internal_host_services",
			Severity:    "high",
			Target:      a.state.Target,
			Description: "Internal host services discovered via pivot",
			Evidence:    result.Result,
			Timestamp:   time.Now(),
		})
	}
}

func (a *PostExploitAgent) dockerRegistryCheck(ctx context.Context) {
	// Check if port 5000 is open (Docker registry)
	if !a.state.HasPort(5000) {
		return
	}

	target := fmt.Sprintf("%s:5000", a.state.Target)
	actionKey := "docker_registry_check:" + target

	if a.state.IsActionDone(actionKey) {
		return
	}

	a.reportAction("docker_registry_check", target)
	a.actions++

	// Docker registry check - try to list repositories via HTTP
	// Use the webapp package to check Docker registry API
	url := fmt.Sprintf("http://%s:5000/v2/_catalog", a.state.Target)

	// Simple check using the runner if available, otherwise mark as failed
	// The MCP server has check_docker_registry but we'll do a basic HTTP probe
	if a.runner != nil {
		// Try web_scan on the docker registry
		opts := map[string]interface{}{
			"url":  url,
			"port": 5000,
		}
		result, err := a.executeAction(ctx, "web_scan", url, opts)
		if err == nil && result != nil && result.Success {
			// Check if we got a valid Docker API response
			if strings.Contains(result.Result, "repositories") || strings.Contains(result.Result, "200") {
				a.state.MarkActionComplete(actionKey)
				a.reportFinding(Finding{
					Type:        "docker_registry_unauth",
					Severity:    "critical",
					Target:      target,
					Description: "Docker Registry accessible without authentication - can pull/push images",
					Evidence:    result.Result,
					Timestamp:   time.Now(),
				})
				return
			}
		}
	}

	a.state.MarkActionFailed(actionKey)
}

// ActionResult for web actions
type ActionResult struct {
	Success         bool
	Output          string
	Vulnerabilities []VulnInfo
}

type VulnInfo struct {
	Type        string
	Severity    string
	Description string
}
