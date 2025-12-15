# Multi-Agent Pentest Architecture

## Overview

Parallel agents working together to speed up penetration testing while sharing discovered information.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    COORDINATOR                          │
│  - Manages shared state (ports, creds, vulns)           │
│  - Spawns/coordinates agents                            │
│  - Aggregates results                                   │
│  - Handles inter-agent communication                    │
└─────────────────────┬───────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
┌─────────┐    ┌─────────────┐    ┌─────────────┐
│  RECON  │    │   SERVICE   │    │ POST-EXPLOIT│
│  AGENT  │───▶│   AGENTS    │───▶│   AGENT     │
└─────────┘    └─────────────┘    └─────────────┘
Port scan      - Web Agent          - Cred spray
Service ID     - Auth Agent         - DB enum
               - RPC Agent          - Hash crack
               - SSL Agent          - Pivot
```

## Agents

### 1. Recon Agent
**Purpose:** Initial reconnaissance and service discovery

**Actions:**
- `full_scan` - Port scanning
- `service_scan` - Banner grabbing
- `banner_grab` - Version identification

**Outputs:**
- Open ports list
- Service identification
- Version information

**Triggers:** Starts first, spawns Service Agents when ports discovered

---

### 2. Web Agent
**Purpose:** Web application vulnerability testing

**Triggers:** Activated when HTTP/HTTPS ports found (80, 443, 8080, 3000, etc.)

**Actions:**
- `web_scan` - Full web vulnerability scan
- `sqli` - SQL injection testing
- `cmd_inject` - Command injection testing
- `lfi_exploit` - Local file inclusion
- `dir_bruteforce` - Directory enumeration
- `xss_scan` - Cross-site scripting
- `api_fuzz` - API endpoint discovery

**Outputs:**
- Web vulnerabilities
- Discovered endpoints
- Potential credentials from forms

---

### 3. Auth Agent
**Purpose:** Authentication and credential testing

**Triggers:** Activated when auth services found (SSH, FTP, etc.)

**Actions:**
- `ssh_login` - SSH brute force
- `ftp_anon` - FTP anonymous login
- `redis_check` - Redis no-auth check
- `mongodb_check` - MongoDB no-auth check

**Outputs:**
- Valid credentials
- No-auth access findings

**Note:** Does NOT run mysql_check/postgres_check - those need creds first!

---

### 4. RPC Agent
**Purpose:** RPC service exploitation

**Triggers:** Activated when RPC ports found (8086, 8087, 50051, 1099, 111)

**Actions:**
- `xmlrpc_exploit` - XML-RPC RCE
- `jsonrpc_exploit` - JSON-RPC secrets
- `grpc_exploit` - gRPC RCE
- `rmi_exploit` - Java RMI deserialization
- `rpcbind_scan` - NFS/NIS enumeration
- `nfs_exploit` - NFS share mounting

**Outputs:**
- RCE vulnerabilities
- Leaked secrets/credentials

---

### 5. SSL Agent
**Purpose:** SSL/TLS security assessment

**Triggers:** Activated when HTTPS ports found (443, 8443, etc.)

**Actions:**
- `ssl_scan` - Full SSL/TLS vulnerability scan
- `ssl_connect` - SSL traffic monitoring

**Outputs:**
- Weak TLS versions
- Expired certificates
- Weak ciphers
- Self-signed certs

---

### 6. Post-Exploit Agent
**Purpose:** Post-exploitation after credentials found

**Triggers:** Activated when ANY credentials discovered

**Actions:**
- `cred_spray` - Test creds on MySQL/PostgreSQL/FTP
- `ssh_recon` - SSH post-exploitation recon
- `ssh_pivot` - Internal network discovery
- `pivot_scan` - Deep scan internal hosts
- `db_enum` - Database enumeration and hash extraction
- `crack_hash` - Password hash cracking

**Outputs:**
- Additional credentials from password reuse
- Database contents
- Cracked passwords
- Internal network map

---

## Shared State

All agents share access to a central state containing:

```go
type SharedState struct {
    mu              sync.RWMutex

    // Discovery
    OpenPorts       []PortInfo
    Services        []ServiceInfo
    DiscoveredHosts []HostInfo

    // Credentials
    Credentials     []Credential
    CrackedHashes   []CrackedHash

    // Vulnerabilities
    Vulnerabilities []Finding

    // Progress
    CompletedActions map[string]bool
    FailedActions    map[string]int
}
```

## Workflow

### Phase 1: Reconnaissance
```
1. Coordinator spawns Recon Agent
2. Recon Agent performs full_scan
3. Open ports added to SharedState
4. Coordinator analyzes ports, spawns appropriate Service Agents
```

### Phase 2: Service Testing (Parallel)
```
Coordinator spawns agents based on discovered ports:

Port 80/443/8080  → Web Agent
Port 22/2222      → Auth Agent (SSH)
Port 21           → Auth Agent (FTP)
Port 6379         → Auth Agent (Redis)
Port 27017        → Auth Agent (MongoDB)
Port 8086         → RPC Agent (XML-RPC)
Port 8087         → RPC Agent (JSON-RPC)
Port 50051        → RPC Agent (gRPC)
Port 443          → SSL Agent

All agents run in parallel, updating SharedState
```

### Phase 3: Post-Exploitation (Triggered)
```
When credentials appear in SharedState:
1. Coordinator spawns Post-Exploit Agent
2. Post-Exploit Agent runs cred_spray
3. If database access gained → db_enum → crack_hash
4. If SSH access → ssh_recon → ssh_pivot → pivot_scan
```

### Phase 4: Reporting
```
1. Coordinator waits for all agents to complete
2. Aggregates findings from SharedState
3. Generates report
```

## Inter-Agent Communication

Agents communicate via SharedState with event notifications:

```go
// Agent publishes event
coordinator.Publish(Event{
    Type:   "credential_found",
    Source: "auth_agent",
    Data:   credential,
})

// Post-Exploit Agent subscribes to credential events
coordinator.Subscribe("credential_found", func(e Event) {
    // Trigger cred_spray
})
```

## Parallelism Analysis

### Fully Parallel (No Dependencies)
These agents can run simultaneously after port scan:
```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Web Agent│  │Auth Agent│  │RPC Agent │  │SSL Agent │
│ (80,8080)│  │(22,21,   │  │(8086,    │  │  (443)   │
│          │  │6379,27017│  │8087,50051│  │          │
└──────────┘  └──────────┘  └──────────┘  └──────────┘
     ↓              ↓             ↓             ↓
   vulns         creds         creds+RCE      vulns
```

### Sequential Dependencies
```
Recon Agent ──► [All Service Agents] (must wait for ports)

Auth Agent finds creds ──► Post-Exploit Agent (must wait for creds)

Post-Exploit: cred_spray ──► db_enum ──► crack_hash (sequential chain)
```

### Optimized Timeline
```
Time ──────────────────────────────────────────────────────────────►

T0   [RECON: port scan]
      │
T1    └──► [WEB]──────────────────────────────►
           [AUTH]─────────┐
           [RPC]──────────┼──────────────────►
           [SSL]──────────┘
                          │
T2                        └─creds found─► [POST-EXPLOIT]────────►
                                           cred_spray
                                           db_enum
                                           crack_hash

Total time: T0 + max(T1_agents) + T2_post_exploit
vs Sequential: T0 + T1_web + T1_auth + T1_rpc + T1_ssl + T2

Speedup: ~3-4x for service testing phase!
```

### Avoiding Bottlenecks

1. **Don't wait for all service agents** - Post-Exploit starts as soon as ANY creds found
2. **Parallel hash cracking** - Can crack multiple hashes simultaneously
3. **Early cred_spray** - Run immediately when creds found, don't wait for other agents
4. **Non-blocking events** - Agents publish events without waiting for response

### What CANNOT Be Parallelized
- Port scan must complete before service agents start
- cred_spray needs at least one credential
- db_enum needs database access from cred_spray
- crack_hash needs hashes from db_enum
- ssh_pivot needs ssh_recon to complete first

## Benefits

1. **Speed**: 3-4x faster on service testing phase
2. **Efficiency**: No wasted actions (agents only run relevant checks)
3. **Coordination**: Agents share discoveries in real-time
4. **Reactive**: Post-exploitation triggers immediately when creds found
5. **Scalable**: Easy to add new specialized agents
6. **Non-blocking**: Agents don't wait on each other unnecessarily

## Implementation Files

- `internal/ai/coordinator.go` - Main coordinator logic
- `internal/ai/agents.go` - Agent definitions
- `internal/ai/shared_state.go` - Shared state management
- `internal/ai/events.go` - Event system for inter-agent communication

## Example Run

```
[COORDINATOR] Starting pentest of 127.0.0.1
[COORDINATOR] Spawning Recon Agent

[RECON] Starting full port scan...
[RECON] Found 12 open ports
[RECON] Publishing: ports_discovered

[COORDINATOR] Received ports_discovered
[COORDINATOR] Spawning Web Agent (ports: 80, 443, 8080)
[COORDINATOR] Spawning Auth Agent (ports: 22, 21, 6379, 27017)
[COORDINATOR] Spawning RPC Agent (ports: 8086, 8087, 50051)
[COORDINATOR] Spawning SSL Agent (ports: 443)

[WEB] Testing http://127.0.0.1:80 for SQLi...
[AUTH] Checking Redis no-auth on 6379...
[RPC] Testing XML-RPC on 8086...
[SSL] Scanning SSL/TLS on 443...

[AUTH] Found credentials: admin:admin123 on SSH:2222
[AUTH] Publishing: credential_found

[COORDINATOR] Received credential_found
[COORDINATOR] Spawning Post-Exploit Agent

[POST-EXPLOIT] Running cred_spray with admin:admin123...
[POST-EXPLOIT] MySQL login successful!
[POST-EXPLOIT] PostgreSQL login successful!
[POST-EXPLOIT] Running db_enum...
[POST-EXPLOIT] Extracted 8 password hashes
[POST-EXPLOIT] Cracking hashes...

[COORDINATOR] All agents complete
[COORDINATOR] Generating report...
```
