package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Adaptive Exploitation Intelligence (AEI)
// Learns from past exploitation attempts to optimize attack paths

// ActionOutcome records the result of a single action
type ActionOutcome struct {
	Action      string        `json:"action"`
	Target      string        `json:"target"`
	Success     bool          `json:"success"`
	Duration    time.Duration `json:"duration_ns"`
	Findings    int           `json:"findings"`      // vulns/creds found
	LeadsToRoot bool          `json:"leads_to_root"` // did this path lead to root?
	Context     ActionContext `json:"context"`       // what was known when action was taken
	Timestamp   time.Time     `json:"timestamp"`
}

// ActionContext captures the state when an action was taken
type ActionContext struct {
	OpenPorts    []int    `json:"open_ports"`
	Services     []string `json:"services"`     // detected services
	HasCreds     bool     `json:"has_creds"`    // did we have creds already?
	PriorActions []string `json:"prior_actions"` // what actions led here
}

// ExploitChain represents a successful sequence of actions
type ExploitChain struct {
	Actions     []string      `json:"actions"`
	TotalTime   time.Duration `json:"total_time_ns"`
	Findings    int           `json:"findings"`
	ReachedRoot bool          `json:"reached_root"`
	StartContext ActionContext `json:"start_context"`
	RunID       string        `json:"run_id"`
	Timestamp   time.Time     `json:"timestamp"`
}

// ActionScore represents learned effectiveness of an action
type ActionScore struct {
	Action         string  `json:"action"`
	SuccessRate    float64 `json:"success_rate"`
	AvgFindings    float64 `json:"avg_findings"`
	AvgDuration    float64 `json:"avg_duration_ms"`
	RootPathRate   float64 `json:"root_path_rate"` // how often this leads to root
	TotalAttempts  int     `json:"total_attempts"`
	EfficiencyScore float64 `json:"efficiency_score"` // composite score
}

// ContextualRecommendation suggests actions based on current context
type ContextualRecommendation struct {
	Action      string  `json:"action"`
	Confidence  float64 `json:"confidence"`  // 0-1
	Reasoning   string  `json:"reasoning"`
	HistoricalSuccess float64 `json:"historical_success"`
}

// AEI is the Adaptive Exploitation Intelligence engine
type AEI struct {
	mu sync.RWMutex

	// Historical data
	Outcomes []ActionOutcome `json:"outcomes"`
	Chains   []ExploitChain  `json:"chains"`

	// Learned scores
	ActionScores map[string]*ActionScore `json:"action_scores"`

	// Pattern matching: context hash -> best actions
	ContextPatterns map[string][]string `json:"context_patterns"`

	// Current run tracking
	currentRunID     string
	currentRunStart  time.Time
	currentOutcomes  []ActionOutcome
	currentContext   ActionContext

	// Config
	dataPath string
}

// NewAEI creates a new Adaptive Exploitation Intelligence engine
func NewAEI(dataPath string) *AEI {
	aei := &AEI{
		ActionScores:    make(map[string]*ActionScore),
		ContextPatterns: make(map[string][]string),
		dataPath:        dataPath,
	}

	// Load existing training data
	aei.Load()

	return aei
}

// StartRun begins tracking a new exploitation run
func (a *AEI) StartRun(target string, openPorts []int, services []string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.currentRunID = fmt.Sprintf("%s_%d", target, time.Now().Unix())
	a.currentRunStart = time.Now()
	a.currentOutcomes = []ActionOutcome{}
	a.currentContext = ActionContext{
		OpenPorts:    openPorts,
		Services:     services,
		HasCreds:     false,
		PriorActions: []string{},
	}
}

// RecordAction records an action outcome during a run
func (a *AEI) RecordAction(action, target string, success bool, duration time.Duration, findings int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	outcome := ActionOutcome{
		Action:    action,
		Target:    target,
		Success:   success,
		Duration:  duration,
		Findings:  findings,
		Context:   a.currentContext,
		Timestamp: time.Now(),
	}

	a.currentOutcomes = append(a.currentOutcomes, outcome)

	// Update context for next action
	a.currentContext.PriorActions = append(a.currentContext.PriorActions, action)
	if findings > 0 && (action == "ssh_login" || action == "check_redis" || action == "check_mysql") {
		a.currentContext.HasCreds = true
	}
}

// EndRun finalizes a run and updates learning
func (a *AEI) EndRun(reachedRoot bool, totalFindings int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Mark outcomes that led to root
	if reachedRoot {
		for i := range a.currentOutcomes {
			a.currentOutcomes[i].LeadsToRoot = true
		}
	}

	// Store outcomes
	a.Outcomes = append(a.Outcomes, a.currentOutcomes...)

	// Create exploit chain if successful
	if totalFindings > 0 || reachedRoot {
		actions := make([]string, len(a.currentOutcomes))
		for i, o := range a.currentOutcomes {
			actions[i] = o.Action
		}

		chain := ExploitChain{
			Actions:      actions,
			TotalTime:    time.Since(a.currentRunStart),
			Findings:     totalFindings,
			ReachedRoot:  reachedRoot,
			StartContext: ActionContext{
				OpenPorts: a.currentContext.OpenPorts,
				Services:  a.currentContext.Services,
			},
			RunID:     a.currentRunID,
			Timestamp: time.Now(),
		}
		a.Chains = append(a.Chains, chain)
	}

	// Recalculate scores
	a.recalculateScores()

	// Update context patterns
	a.updateContextPatterns()

	// Save to disk
	a.save()
}

// recalculateScores updates action scores based on all outcomes
func (a *AEI) recalculateScores() {
	// Reset scores
	a.ActionScores = make(map[string]*ActionScore)

	// Group outcomes by action
	actionOutcomes := make(map[string][]ActionOutcome)
	for _, o := range a.Outcomes {
		actionOutcomes[o.Action] = append(actionOutcomes[o.Action], o)
	}

	// Calculate scores
	for action, outcomes := range actionOutcomes {
		score := &ActionScore{
			Action:        action,
			TotalAttempts: len(outcomes),
		}

		var successCount, rootCount int
		var totalFindings int
		var totalDuration time.Duration

		for _, o := range outcomes {
			if o.Success {
				successCount++
			}
			if o.LeadsToRoot {
				rootCount++
			}
			totalFindings += o.Findings
			totalDuration += o.Duration
		}

		score.SuccessRate = float64(successCount) / float64(len(outcomes))
		score.AvgFindings = float64(totalFindings) / float64(len(outcomes))
		score.AvgDuration = float64(totalDuration.Milliseconds()) / float64(len(outcomes))
		score.RootPathRate = float64(rootCount) / float64(len(outcomes))

		// Efficiency score: high success + high findings + leads to root - time penalty
		// Normalized to 0-100
		score.EfficiencyScore = (score.SuccessRate * 30) +
			(math.Min(score.AvgFindings, 5) * 10) +
			(score.RootPathRate * 40) -
			(math.Min(score.AvgDuration/10000, 20)) // penalty for slow actions

		a.ActionScores[action] = score
	}
}

// updateContextPatterns learns which actions work best for given contexts
func (a *AEI) updateContextPatterns() {
	// Group successful chains by context signature
	contextChains := make(map[string][]ExploitChain)

	for _, chain := range a.Chains {
		sig := a.contextSignature(chain.StartContext)
		contextChains[sig] = append(contextChains[sig], chain)
	}

	// For each context, find the most efficient action sequence
	for sig, chains := range contextChains {
		// Sort by efficiency (findings/time, weighted by root access)
		sort.Slice(chains, func(i, j int) bool {
			scoreI := float64(chains[i].Findings) / float64(chains[i].TotalTime.Milliseconds()+1)
			if chains[i].ReachedRoot {
				scoreI *= 2
			}
			scoreJ := float64(chains[j].Findings) / float64(chains[j].TotalTime.Milliseconds()+1)
			if chains[j].ReachedRoot {
				scoreJ *= 2
			}
			return scoreI > scoreJ
		})

		// Take the best chain's first 3 actions as the pattern
		if len(chains) > 0 && len(chains[0].Actions) > 0 {
			maxActions := 3
			if len(chains[0].Actions) < maxActions {
				maxActions = len(chains[0].Actions)
			}
			// Initialize map if nil
			if a.ContextPatterns == nil {
				a.ContextPatterns = make(map[string][]string)
			}
			a.ContextPatterns[sig] = chains[0].Actions[:maxActions]
		}
	}
}

// contextSignature creates a hash-like string for a context
func (a *AEI) contextSignature(ctx ActionContext) string {
	// Simplified signature based on key ports
	sig := ""

	portMap := map[int]string{
		21: "ftp", 22: "ssh", 80: "http", 443: "https",
		3306: "mysql", 5432: "postgres", 6379: "redis",
		27017: "mongo", 8080: "http-alt", 2222: "ssh-alt",
	}

	for _, port := range ctx.OpenPorts {
		if name, ok := portMap[port]; ok {
			sig += name + ","
		}
	}

	return sig
}

// GetRecommendations returns prioritized action recommendations
func (a *AEI) GetRecommendations(ctx ActionContext, availableActions []string) []ContextualRecommendation {
	a.mu.RLock()
	defer a.mu.RUnlock()

	recommendations := []ContextualRecommendation{}

	// Check for matching context pattern
	sig := a.contextSignature(ctx)
	if pattern, ok := a.ContextPatterns[sig]; ok && len(pattern) > 0 {
		// We have a learned pattern for this context
		for i, action := range pattern {
			// Skip actions already taken
			taken := false
			for _, prior := range ctx.PriorActions {
				if prior == action {
					taken = true
					break
				}
			}
			if taken {
				continue
			}

			rec := ContextualRecommendation{
				Action:     action,
				Confidence: 0.9 - float64(i)*0.1, // decreasing confidence
				Reasoning:  fmt.Sprintf("Learned pattern: %s is action #%d for this port combination", action, i+1),
			}
			if score, ok := a.ActionScores[action]; ok {
				rec.HistoricalSuccess = score.SuccessRate
			}
			recommendations = append(recommendations, rec)
		}
	}

	// Add score-based recommendations
	scored := []ContextualRecommendation{}
	for _, action := range availableActions {
		// Skip already recommended or taken
		skip := false
		for _, rec := range recommendations {
			if rec.Action == action {
				skip = true
				break
			}
		}
		for _, prior := range ctx.PriorActions {
			if prior == action {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		score, hasScore := a.ActionScores[action]
		if hasScore && score.TotalAttempts >= 3 {
			rec := ContextualRecommendation{
				Action:            action,
				Confidence:        score.EfficiencyScore / 100,
				Reasoning:         fmt.Sprintf("Efficiency score: %.1f (success: %.0f%%, avg findings: %.1f)", score.EfficiencyScore, score.SuccessRate*100, score.AvgFindings),
				HistoricalSuccess: score.SuccessRate,
			}
			scored = append(scored, rec)
		}
	}

	// Sort scored by confidence
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Confidence > scored[j].Confidence
	})

	recommendations = append(recommendations, scored...)

	return recommendations
}

// GetPromptContext generates context for the AI prompt
func (a *AEI) GetPromptContext(ctx ActionContext) string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.Outcomes) == 0 {
		return "" // No training data yet
	}

	var sb string
	sb = "\n\n=== ADAPTIVE EXPLOITATION INTELLIGENCE ===\n"
	sb += fmt.Sprintf("Based on %d previous actions across %d runs:\n\n", len(a.Outcomes), len(a.Chains))

	// Top performing actions
	sb += "TOP ACTIONS BY EFFICIENCY:\n"

	scores := make([]*ActionScore, 0, len(a.ActionScores))
	for _, s := range a.ActionScores {
		if s.TotalAttempts >= 2 {
			scores = append(scores, s)
		}
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].EfficiencyScore > scores[j].EfficiencyScore
	})

	for i, s := range scores {
		if i >= 5 {
			break
		}
		sb += fmt.Sprintf("  %d. %s - %.0f%% success, %.1f avg findings, %.0f%% leads to root\n",
			i+1, s.Action, s.SuccessRate*100, s.AvgFindings, s.RootPathRate*100)
	}

	// Context-specific recommendation
	sig := a.contextSignature(ctx)
	if pattern, ok := a.ContextPatterns[sig]; ok {
		sb += fmt.Sprintf("\nRECOMMENDED SEQUENCE for ports [%s]:\n", sig)
		for i, action := range pattern {
			sb += fmt.Sprintf("  %d. %s\n", i+1, action)
		}
	}

	// Actions to avoid (low success, slow)
	sb += "\nLOW VALUE ACTIONS (consider skipping):\n"
	for _, s := range scores {
		if s.SuccessRate < 0.2 && s.TotalAttempts >= 3 {
			sb += fmt.Sprintf("  - %s (%.0f%% success after %d attempts)\n", s.Action, s.SuccessRate*100, s.TotalAttempts)
		}
	}

	sb += "===========================================\n"

	return sb
}

// Save persists training data to disk
func (a *AEI) save() {
	if a.dataPath == "" {
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(a.dataPath)
	os.MkdirAll(dir, 0755)

	data, err := json.MarshalIndent(struct {
		Outcomes        []ActionOutcome           `json:"outcomes"`
		Chains          []ExploitChain            `json:"chains"`
		ActionScores    map[string]*ActionScore   `json:"action_scores"`
		ContextPatterns map[string][]string       `json:"context_patterns"`
		LastUpdated     time.Time                 `json:"last_updated"`
	}{
		Outcomes:        a.Outcomes,
		Chains:          a.Chains,
		ActionScores:    a.ActionScores,
		ContextPatterns: a.ContextPatterns,
		LastUpdated:     time.Now(),
	}, "", "  ")

	if err != nil {
		fmt.Printf("[AEI] Error marshaling data: %v\n", err)
		return
	}

	if err := os.WriteFile(a.dataPath, data, 0644); err != nil {
		fmt.Printf("[AEI] Error saving data: %v\n", err)
	}
}

// Load reads training data from disk
func (a *AEI) Load() {
	if a.dataPath == "" {
		return
	}

	data, err := os.ReadFile(a.dataPath)
	if err != nil {
		// No existing data, start fresh
		return
	}

	var loaded struct {
		Outcomes        []ActionOutcome           `json:"outcomes"`
		Chains          []ExploitChain            `json:"chains"`
		ActionScores    map[string]*ActionScore   `json:"action_scores"`
		ContextPatterns map[string][]string       `json:"context_patterns"`
	}

	if err := json.Unmarshal(data, &loaded); err != nil {
		fmt.Printf("[AEI] Error loading data: %v\n", err)
		return
	}

	a.Outcomes = loaded.Outcomes
	a.Chains = loaded.Chains
	a.ActionScores = loaded.ActionScores
	a.ContextPatterns = loaded.ContextPatterns

	fmt.Printf("[AEI] Loaded %d outcomes, %d chains from training data\n", len(a.Outcomes), len(a.Chains))
}

// GetStats returns current learning statistics
func (a *AEI) GetStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_outcomes":   len(a.Outcomes),
		"total_chains":     len(a.Chains),
		"actions_learned":  len(a.ActionScores),
		"patterns_learned": len(a.ContextPatterns),
	}
}
