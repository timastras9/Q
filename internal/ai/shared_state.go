package ai

import (
	"sync"
	"time"
)

// EventType represents different event types for inter-agent communication
type EventType string

const (
	EventPortsDiscovered    EventType = "ports_discovered"
	EventCredentialFound    EventType = "credential_found"
	EventVulnerabilityFound EventType = "vulnerability_found"
	EventHashExtracted      EventType = "hash_extracted"
	EventHashCracked        EventType = "hash_cracked"
	EventAgentComplete      EventType = "agent_complete"
	EventAgentError         EventType = "agent_error"
)

// Event represents an inter-agent communication event
type Event struct {
	Type      EventType
	Source    string // Agent name that generated the event
	Timestamp time.Time
	Data      interface{}
}

// Credential represents discovered credentials (compatible with CredentialFind)
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash,omitempty"`
	Service  string `json:"service"`
	Target   string `json:"target"`
}

// PortInfoExt extends PortInfo with service details for agent use
type PortInfoExt struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// ScanState represents the final scan results
type ScanState struct {
	Target          string       `json:"target"`
	OpenPorts       []PortInfo   `json:"open_ports"`
	Credentials     []Credential `json:"credentials"`
	Vulnerabilities []Finding    `json:"vulnerabilities"`
	ActionHistory   []Action     `json:"action_history"`
	DiscoveredHosts []HostInfo   `json:"discovered_hosts"`
}

// SharedState holds all state shared between agents
type SharedState struct {
	mu sync.RWMutex

	// Target info
	Target string

	// Discovery
	OpenPorts       []PortInfo
	Services        map[int]string // port -> service name
	DiscoveredHosts []HostInfo

	// Credentials
	Credentials   []Credential
	CrackedHashes map[string]string // hash -> plaintext

	// Vulnerabilities
	Vulnerabilities []Finding

	// Progress tracking
	CompletedActions map[string]bool
	FailedActions    map[string]int
	ActionHistory    []Action

	// Event subscribers
	subscribers map[EventType][]func(Event)

	// Agent status
	AgentStatus map[string]AgentStatusInfo
}

// AgentStatusInfo tracks individual agent status
type AgentStatusInfo struct {
	Name      string
	Status    string // "running", "completed", "error"
	StartTime time.Time
	EndTime   time.Time
	Actions   int
	Findings  int
	Error     string
}

// NewSharedState creates a new shared state instance
func NewSharedState(target string) *SharedState {
	return &SharedState{
		Target:           target,
		Services:         make(map[int]string),
		CrackedHashes:    make(map[string]string),
		CompletedActions: make(map[string]bool),
		FailedActions:    make(map[string]int),
		subscribers:      make(map[EventType][]func(Event)),
		AgentStatus:      make(map[string]AgentStatusInfo),
	}
}

// Subscribe registers a callback for an event type
func (s *SharedState) Subscribe(eventType EventType, callback func(Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers[eventType] = append(s.subscribers[eventType], callback)
}

// Publish sends an event to all subscribers
func (s *SharedState) Publish(event Event) {
	s.mu.RLock()
	callbacks := s.subscribers[event.Type]
	s.mu.RUnlock()

	event.Timestamp = time.Now()
	for _, cb := range callbacks {
		go cb(event) // Non-blocking
	}
}

// AddPort adds a discovered port (thread-safe)
func (s *SharedState) AddPort(port PortInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already exists
	for _, p := range s.OpenPorts {
		if p.Port == port.Port {
			return
		}
	}
	s.OpenPorts = append(s.OpenPorts, port)
	// Services map is populated separately by the caller
}

// AddPorts adds multiple ports and publishes event
func (s *SharedState) AddPorts(ports []PortInfo) {
	for _, p := range ports {
		s.AddPort(p)
	}
	s.Publish(Event{
		Type:   EventPortsDiscovered,
		Source: "recon",
		Data:   ports,
	})
}

// GetPorts returns a copy of open ports (thread-safe)
func (s *SharedState) GetPorts() []PortInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]PortInfo, len(s.OpenPorts))
	copy(result, s.OpenPorts)
	return result
}

// HasPort checks if a port is open
func (s *SharedState) HasPort(port int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, p := range s.OpenPorts {
		if p.Port == port {
			return true
		}
	}
	return false
}

// AddCredential adds a discovered credential (thread-safe)
func (s *SharedState) AddCredential(cred Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already exists
	for _, c := range s.Credentials {
		if c.Username == cred.Username && c.Password == cred.Password && c.Service == cred.Service {
			return
		}
	}
	s.Credentials = append(s.Credentials, cred)

	// Publish event (unlock first to avoid deadlock)
	s.mu.Unlock()
	s.Publish(Event{
		Type:   EventCredentialFound,
		Source: cred.Service,
		Data:   cred,
	})
	s.mu.Lock()
}

// GetCredentials returns a copy of credentials (thread-safe)
func (s *SharedState) GetCredentials() []Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Credential, len(s.Credentials))
	copy(result, s.Credentials)
	return result
}

// HasUsableCredentials checks if we have username:password pairs
func (s *SharedState) HasUsableCredentials() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.Credentials {
		if c.Username != "" && c.Password != "" {
			return true
		}
	}
	return false
}

// AddVulnerability adds a discovered vulnerability (thread-safe)
func (s *SharedState) AddVulnerability(vuln Finding) {
	s.mu.Lock()
	s.Vulnerabilities = append(s.Vulnerabilities, vuln)
	s.mu.Unlock()

	s.Publish(Event{
		Type:   EventVulnerabilityFound,
		Source: vuln.Type,
		Data:   vuln,
	})
}

// GetVulnerabilities returns a copy of vulnerabilities
func (s *SharedState) GetVulnerabilities() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Finding, len(s.Vulnerabilities))
	copy(result, s.Vulnerabilities)
	return result
}

// AddCrackedHash records a cracked hash
func (s *SharedState) AddCrackedHash(hash, plaintext string) {
	s.mu.Lock()
	s.CrackedHashes[hash] = plaintext
	s.mu.Unlock()

	s.Publish(Event{
		Type:   EventHashCracked,
		Source: "crack",
		Data:   map[string]string{"hash": hash, "plaintext": plaintext},
	})
}

// GetCrackedHash returns plaintext for a hash if cracked
func (s *SharedState) GetCrackedHash(hash string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	plaintext, ok := s.CrackedHashes[hash]
	return plaintext, ok
}

// MarkActionComplete marks an action as completed
func (s *SharedState) MarkActionComplete(action string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CompletedActions[action] = true
}

// MarkActionFailed increments failure count for an action
func (s *SharedState) MarkActionFailed(action string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FailedActions[action]++
}

// IsActionDone checks if an action was completed or failed
func (s *SharedState) IsActionDone(action string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CompletedActions[action] || s.FailedActions[action] > 0
}

// AddAction records an action in history
func (s *SharedState) AddAction(action Action) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActionHistory = append(s.ActionHistory, action)
}

// UpdateAgentStatus updates an agent's status
func (s *SharedState) UpdateAgentStatus(name, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info := s.AgentStatus[name]
	info.Name = name
	info.Status = status
	if status == "running" && info.StartTime.IsZero() {
		info.StartTime = time.Now()
	}
	if status == "completed" || status == "error" {
		info.EndTime = time.Now()
	}
	s.AgentStatus[name] = info
}

// GetAgentStatus returns status for all agents
func (s *SharedState) GetAgentStatus() map[string]AgentStatusInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]AgentStatusInfo)
	for k, v := range s.AgentStatus {
		result[k] = v
	}
	return result
}

// ToScanState converts SharedState to the existing ScanState format for compatibility
func (s *SharedState) ToScanState() *ScanState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &ScanState{
		Target:           s.Target,
		OpenPorts:        s.OpenPorts,
		Credentials:      s.Credentials,
		Vulnerabilities:  s.Vulnerabilities,
		ActionHistory:    s.ActionHistory,
		DiscoveredHosts:  s.DiscoveredHosts,
	}
}
