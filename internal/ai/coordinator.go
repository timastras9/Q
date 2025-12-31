package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"pentestai/internal/exploit"
)

// AgentType identifies the type of agent
type AgentType string

const (
	AgentTypeRecon       AgentType = "recon"
	AgentTypeWeb         AgentType = "web"
	AgentTypeAuth        AgentType = "auth"
	AgentTypeRPC         AgentType = "rpc"
	AgentTypeSSL         AgentType = "ssl"
	AgentTypePostExploit AgentType = "post_exploit"
)

// Agent interface that all agents must implement
type Agent interface {
	Name() string
	Type() AgentType
	Run(ctx context.Context) error
	Stop()
}

// AgentCallbacks for progress reporting
type AgentCallbacks struct {
	OnAction    func(agent string, action, target string)
	OnFinding   func(agent string, finding Finding)
	OnCredential func(agent string, cred Credential)
	OnComplete  func(agent string, actions int, findings int)
	OnError     func(agent string, err error)
}

// Coordinator manages multiple agents working together
type Coordinator struct {
	state     *SharedState
	framework *exploit.Framework
	aiClient  *ClaudeClient
	callbacks AgentCallbacks

	agents    map[string]Agent
	agentsMu  sync.RWMutex

	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc

	// Configuration
	maxActionsPerAgent int
	timeout           time.Duration
	quickMode         bool
	turboMode         bool // Run AI exploration in parallel, reduced iterations
}

// NewCoordinator creates a new multi-agent coordinator
func NewCoordinator(target string, framework *exploit.Framework, aiClient *ClaudeClient) *Coordinator {
	ctx, cancel := context.WithCancel(context.Background())

	return &Coordinator{
		state:              NewSharedState(target),
		framework:          framework,
		aiClient:           aiClient,
		agents:             make(map[string]Agent),
		ctx:                ctx,
		cancel:             cancel,
		maxActionsPerAgent: 15,
		timeout:            10 * time.Minute,
	}
}

// SetCallbacks sets the progress callbacks
func (c *Coordinator) SetCallbacks(cb AgentCallbacks) {
	c.callbacks = cb
}

// SetMaxActionsPerAgent sets max actions each agent can perform
func (c *Coordinator) SetMaxActionsPerAgent(max int) {
	c.maxActionsPerAgent = max
}

// SetTimeout sets the overall timeout
func (c *Coordinator) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetQuickMode enables quick scan mode (skips AI exploration, faster checks)
func (c *Coordinator) SetQuickMode(quick bool) {
	c.quickMode = quick
}

// SetTurboMode enables turbo mode (AI exploration runs in parallel with agents)
func (c *Coordinator) SetTurboMode(turbo bool) {
	c.turboMode = turbo
}

// GetState returns the shared state
func (c *Coordinator) GetState() *SharedState {
	return c.state
}

// Run executes the multi-agent pentest
func (c *Coordinator) Run(ctx context.Context) error {
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	c.ctx = ctx

	startTime := time.Now()

	// Subscribe to credential events to spawn post-exploit agent
	postExploitSpawned := false
	var postExploitMu sync.Mutex
	c.state.Subscribe(EventCredentialFound, func(e Event) {
		postExploitMu.Lock()
		defer postExploitMu.Unlock()

		// Only spawn once, and only if we have usable creds
		if !postExploitSpawned && c.state.HasUsableCredentials() {
			postExploitSpawned = true
			go c.spawnPostExploitAgent()
		}
	})

	// Phase 1: Recon
	if c.callbacks.OnAction != nil {
		c.callbacks.OnAction("coordinator", "phase", "RECONNAISSANCE")
	}

	reconAgent := NewReconAgent(c.state, c.framework, c.maxActionsPerAgent)
	if err := c.runAgent(ctx, reconAgent); err != nil {
		return fmt.Errorf("recon failed: %w", err)
	}

	// Phase 2: Spawn service agents in parallel based on discovered ports
	if c.callbacks.OnAction != nil {
		c.callbacks.OnAction("coordinator", "phase", "SERVICE TESTING (parallel)")
	}

	c.spawnServiceAgents()

	// In turbo mode, start AI exploration in parallel with service agents
	var aiWg sync.WaitGroup
	if c.turboMode && !c.quickMode && c.aiClient != nil {
		aiWg.Add(1)
		go func() {
			defer aiWg.Done()
			// Wait a bit for initial findings
			time.Sleep(500 * time.Millisecond)
			if c.callbacks.OnAction != nil {
				c.callbacks.OnAction("coordinator", "phase", "AI EXPLORATION (parallel)")
			}
			if err := c.runAIExploration(ctx); err != nil {
				fmt.Printf("[COORDINATOR] AI exploration error: %v\n", err)
			}
		}()
	}

	// Wait for all service agents to complete
	c.wg.Wait()

	// Phase 3: If post-exploit was spawned, wait for it
	// It may have already started from credential event
	if postExploitSpawned {
		// Give it a moment to finish
		time.Sleep(100 * time.Millisecond)
	}

	// Final wait for any remaining agents
	c.wg.Wait()

	// Phase 4: AI Deep Exploration - Let Claude analyze findings and get curious
	// Skip in quick mode and turbo mode (already ran in parallel)
	if !c.quickMode && !c.turboMode {
		if c.aiClient != nil && c.callbacks.OnAction != nil {
			c.callbacks.OnAction("coordinator", "phase", "AI DEEP EXPLORATION")
		}
		if err := c.runAIExploration(ctx); err != nil {
			// Non-fatal - just log it
			fmt.Printf("[COORDINATOR] AI exploration error: %v\n", err)
		}
	}

	// Wait for parallel AI exploration to complete in turbo mode
	if c.turboMode {
		aiWg.Wait()
	}

	// Report completion
	duration := time.Since(startTime)
	vulns := c.state.GetVulnerabilities()
	creds := c.state.GetCredentials()

	if c.callbacks.OnComplete != nil {
		c.callbacks.OnComplete("coordinator",
			len(c.state.ActionHistory),
			len(vulns))
	}

	fmt.Printf("\n[COORDINATOR] Pentest complete in %v\n", duration)
	fmt.Printf("[COORDINATOR] Total findings: %d vulns, %d credentials\n", len(vulns), len(creds))

	return nil
}

// spawnServiceAgents creates agents based on discovered ports
func (c *Coordinator) spawnServiceAgents() {
	ports := c.state.GetPorts()

	// Determine which agents to spawn
	hasWeb := false
	hasSSH := false
	hasFTP := false
	hasRedis := false
	hasMongo := false
	hasRPC := false
	hasSSL := false

	for _, p := range ports {
		switch p.Port {
		case 80, 8080, 3000, 5000, 8081, 8082, 8083, 8084:
			hasWeb = true
		case 443, 8443:
			hasWeb = true
			hasSSL = true
		case 22, 2222:
			hasSSH = true
		case 21:
			hasFTP = true
		case 6379:
			hasRedis = true
		case 27017:
			hasMongo = true
		case 8086, 8087, 50051, 1099, 111:
			hasRPC = true
		}
	}

	// Spawn agents in parallel
	if hasWeb {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			agent := NewWebAgent(c.state, c.framework, c.aiClient, c.maxActionsPerAgent)
			agent.SetCallbacks(c.callbacks)
			c.runAgent(c.ctx, agent)
		}()
	}

	if hasSSH || hasFTP || hasRedis || hasMongo {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			agent := NewAuthAgent(c.state, c.framework, c.aiClient, c.maxActionsPerAgent)
			agent.SetCallbacks(c.callbacks)
			c.runAgent(c.ctx, agent)
		}()
	}

	if hasRPC {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			agent := NewRPCAgent(c.state, c.framework, c.aiClient, c.maxActionsPerAgent)
			agent.SetCallbacks(c.callbacks)
			c.runAgent(c.ctx, agent)
		}()
	}

	if hasSSL {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			agent := NewSSLAgent(c.state, c.framework, c.aiClient, c.maxActionsPerAgent)
			agent.SetCallbacks(c.callbacks)
			c.runAgent(c.ctx, agent)
		}()
	}
}

// spawnPostExploitAgent creates the post-exploitation agent
func (c *Coordinator) spawnPostExploitAgent() {
	c.wg.Add(1)
	defer c.wg.Done()

	if c.callbacks.OnAction != nil {
		c.callbacks.OnAction("coordinator", "spawn", "post_exploit (credentials found!)")
	}

	agent := NewPostExploitAgent(c.state, c.framework, c.aiClient, c.maxActionsPerAgent)
	agent.SetCallbacks(c.callbacks)
	c.runAgent(c.ctx, agent)
}

// runAgent executes a single agent
func (c *Coordinator) runAgent(ctx context.Context, agent Agent) error {
	c.agentsMu.Lock()
	c.agents[agent.Name()] = agent
	c.agentsMu.Unlock()

	c.state.UpdateAgentStatus(agent.Name(), "running")

	err := agent.Run(ctx)

	if err != nil {
		c.state.UpdateAgentStatus(agent.Name(), "error")
		if c.callbacks.OnError != nil {
			c.callbacks.OnError(agent.Name(), err)
		}
	} else {
		c.state.UpdateAgentStatus(agent.Name(), "completed")
	}

	return err
}

// Stop stops all running agents
func (c *Coordinator) Stop() {
	c.cancel()

	c.agentsMu.RLock()
	for _, agent := range c.agents {
		agent.Stop()
	}
	c.agentsMu.RUnlock()
}

// GetResults returns the final scan results
func (c *Coordinator) GetResults() *ScanState {
	return c.state.ToScanState()
}

// runAIExploration uses Claude to analyze agent findings and explore deeper
func (c *Coordinator) runAIExploration(ctx context.Context) error {
	if c.aiClient == nil {
		return nil
	}

	// Create an AutoRunner for AI-driven exploration
	runner := NewAutoRunner(c.aiClient)
	runner.framework = c.framework
	runner.maxActions = c.maxActionsPerAgent

	// Initialize runner state from coordinator state
	runner.state = &PentestState{
		Target: c.state.Target,
		Phase:  "exploitation",
	}

	// Copy discovered data to runner state
	for _, p := range c.state.GetPorts() {
		runner.state.OpenPorts = append(runner.state.OpenPorts, PortInfo{
			Host:     p.Host,
			Port:     p.Port,
			Protocol: p.Protocol,
			State:    p.State,
		})
	}
	for _, cred := range c.state.GetCredentials() {
		runner.state.Credentials = append(runner.state.Credentials, CredentialFind{
			Username: cred.Username,
			Password: cred.Password,
			Hash:     cred.Hash,
			Service:  cred.Service,
			Target:   cred.Target,
		})

		// If SSH credentials were found by other agents, add synthetic ssh_login success
		// This triggers the AI to run ssh_recon and privesc
		if strings.HasPrefix(cred.Service, "ssh") && cred.Username != "" && cred.Password != "" {
			target := cred.Target
			if target == "" {
				target = c.state.Target + ":2222"
			}
			// Check if we already have an ssh_login for this target
			hasSSHLogin := false
			for _, action := range runner.state.ActionHistory {
				if action.Type == "ssh_login" && action.Target == target {
					hasSSHLogin = true
					break
				}
			}
			if !hasSSHLogin {
				runner.state.ActionHistory = append(runner.state.ActionHistory, Action{
					Type:    "ssh_login",
					Target:  target,
					Success: true,
					Result:  fmt.Sprintf("SSH credentials found: %s (from auth agent)", cred.Username),
					Timestamp: time.Now(),
				})
			}
		}
	}
	for _, vuln := range c.state.GetVulnerabilities() {
		runner.state.Vulnerabilities = append(runner.state.Vulnerabilities, vuln)
	}

	// Set callbacks for AI actions
	runner.callbacks = RunnerCallbacks{
		OnActionStart: func(action string, target string) {
			if c.callbacks.OnAction != nil {
				c.callbacks.OnAction("ai_explorer", action, target)
			}
		},
		OnFinding: func(finding Finding) {
			c.state.AddVulnerability(finding)
			if c.callbacks.OnFinding != nil {
				c.callbacks.OnFinding("ai_explorer", finding)
			}
		},
		OnCredential: func(cred CredentialFind) {
			c.state.AddCredential(Credential{
				Username: cred.Username,
				Password: cred.Password,
				Hash:     cred.Hash,
				Service:  cred.Service,
				Target:   cred.Target,
			})
			if c.callbacks.OnCredential != nil {
				c.callbacks.OnCredential("ai_explorer", Credential{
					Username: cred.Username,
					Password: cred.Password,
					Hash:     cred.Hash,
					Service:  cred.Service,
					Target:   cred.Target,
				})
			}
		},
	}

	// Run AI exploration - Claude will analyze findings and decide next actions
	_, err := runner.Run(ctx, c.state.Target, nil)
	return err
}
