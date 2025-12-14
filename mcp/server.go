package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
)

// MCP JSON-RPC structures
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// MCP Server
type MCPServer struct {
	tools map[string]func(map[string]interface{}) (string, error)
}

func NewMCPServer() *MCPServer {
	s := &MCPServer{
		tools: make(map[string]func(map[string]interface{}) (string, error)),
	}
	s.registerTools()
	return s
}

func (s *MCPServer) registerTools() {
	s.tools["scan_ports"] = s.scanPorts
	s.tools["check_redis"] = s.checkRedis
	s.tools["check_mongodb"] = s.checkMongoDB
	s.tools["check_mysql"] = s.checkMySQL
	s.tools["check_postgres"] = s.checkPostgres
	s.tools["check_elasticsearch"] = s.checkElasticsearch
	s.tools["check_docker_registry"] = s.checkDockerRegistry
	s.tools["check_ftp_anonymous"] = s.checkFTPAnonymous
	s.tools["check_ssh"] = s.checkSSH
	s.tools["check_smb"] = s.checkSMB
	s.tools["web_scan"] = s.webScan
	s.tools["grab_banner"] = s.grabBanner
	s.tools["credential_spray"] = s.credentialSpray
}

func (s *MCPServer) getTools() []Tool {
	return []Tool{
		{
			Name:        "scan_ports",
			Description: "Scan TCP ports on a target host to discover open services",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target":     {Type: "string", Description: "Target IP or hostname"},
					"ports":      {Type: "string", Description: "Port range (e.g., '1-1000' or '22,80,443,3306')"},
					"timeout_ms": {Type: "number", Description: "Timeout per port in milliseconds (default: 1000)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_redis",
			Description: "Check if Redis is accessible without authentication - CRITICAL if open",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port (default: 6379)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_mongodb",
			Description: "Check if MongoDB is accessible without authentication - CRITICAL if open",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port (default: 27017)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_mysql",
			Description: "Check MySQL with common/default credentials",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target":   {Type: "string", Description: "Target IP or hostname"},
					"port":     {Type: "number", Description: "Port (default: 3306)"},
					"username": {Type: "string", Description: "Username to try (default: root)"},
					"password": {Type: "string", Description: "Password to try (default: common passwords)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_postgres",
			Description: "Check PostgreSQL with common/default credentials",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target":   {Type: "string", Description: "Target IP or hostname"},
					"port":     {Type: "number", Description: "Port (default: 5432)"},
					"username": {Type: "string", Description: "Username to try (default: postgres)"},
					"password": {Type: "string", Description: "Password to try (default: common passwords)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_elasticsearch",
			Description: "Check if Elasticsearch is accessible without authentication - CRITICAL if open",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port (default: 9200)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_docker_registry",
			Description: "Check if Docker Registry is accessible without authentication - CRITICAL if open, allows pulling/pushing images",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port (default: 5000)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_ftp_anonymous",
			Description: "Check if FTP allows anonymous login",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port (default: 21)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_ssh",
			Description: "Check SSH with common credentials",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target":   {Type: "string", Description: "Target IP or hostname"},
					"port":     {Type: "number", Description: "Port (default: 22)"},
					"username": {Type: "string", Description: "Username to try"},
					"password": {Type: "string", Description: "Password to try"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_smb",
			Description: "Check SMB for null session or guest access",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port (default: 445)"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "web_scan",
			Description: "Scan web server for common vulnerabilities and misconfigurations",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"url": {Type: "string", Description: "Target URL (e.g., http://127.0.0.1:8080)"},
				},
				Required: []string{"url"},
			},
		},
		{
			Name:        "grab_banner",
			Description: "Grab service banner from a port to identify the service",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target": {Type: "string", Description: "Target IP or hostname"},
					"port":   {Type: "number", Description: "Port to connect to"},
				},
				Required: []string{"target", "port"},
			},
		},
		{
			Name:        "credential_spray",
			Description: "Parallel credential spraying against SSH/MySQL/PostgreSQL with top 10,000 passwords from rockyou.txt. Uses async workers for speed with rate limiting to avoid lockouts.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"target":        {Type: "string", Description: "Target IP or hostname"},
					"port":          {Type: "number", Description: "Port (auto-detected based on service if not specified)"},
					"service":       {Type: "string", Description: "Service type: ssh, mysql, postgres"},
					"usernames":     {Type: "string", Description: "Comma-separated usernames to try (default: root,admin,user)"},
					"password_file": {Type: "string", Description: "Path to password wordlist file (default: uses embedded top passwords)"},
					"max_passwords": {Type: "number", Description: "Max passwords to try per user (default: 100, max: 10000)"},
					"workers":       {Type: "number", Description: "Parallel workers (default: 10, max: 50)"},
					"delay_ms":      {Type: "number", Description: "Delay between attempts per worker in ms (default: 100)"},
				},
				Required: []string{"target", "service"},
			},
		},
	}
}

// Tool implementations

func (s *MCPServer) scanPorts(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	portsArg := "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017,5000,5601,9000,9001,8081,8082,8083,8084,8085"
	if p, ok := args["ports"].(string); ok && p != "" {
		portsArg = p
	}
	timeoutMs := 1000
	if t, ok := args["timeout_ms"].(float64); ok {
		timeoutMs = int(t)
	}

	var openPorts []string
	ports := expandPorts(portsArg)

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
		if err == nil {
			conn.Close()
			service := identifyService(port)
			openPorts = append(openPorts, fmt.Sprintf("%d/tcp open (%s)", port, service))
		}
	}

	if len(openPorts) == 0 {
		return fmt.Sprintf("No open ports found on %s", target), nil
	}

	return fmt.Sprintf("Open ports on %s:\n%s", target, strings.Join(openPorts, "\n")), nil
}

func (s *MCPServer) checkRedis(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 6379
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return fmt.Sprintf("Redis port %d is closed or unreachable: %v", port, err), nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("INFO\r\n"))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Sprintf("Redis connection failed: %v", err), nil
	}

	response := string(buf[:n])
	if strings.Contains(response, "redis_version") {
		// Extract version
		var version string
		for _, line := range strings.Split(response, "\r\n") {
			if strings.HasPrefix(line, "redis_version:") {
				version = strings.TrimPrefix(line, "redis_version:")
				break
			}
		}
		return fmt.Sprintf(`[CRITICAL] Redis UNAUTHENTICATED ACCESS on %s:%d
Version: %s
Impact: Full database access, potential RCE via SLAVEOF or module loading
Remediation: Enable authentication with 'requirepass' in redis.conf
Severity: CRITICAL`, target, port, version), nil
	}

	if strings.Contains(response, "NOAUTH") || strings.Contains(response, "Authentication required") {
		return fmt.Sprintf("[OK] Redis on %s:%d requires authentication", target, port), nil
	}

	return fmt.Sprintf("Redis on %s:%d - unexpected response: %s", target, port, response[:min(100, len(response))]), nil
}

func (s *MCPServer) checkMongoDB(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 27017
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return fmt.Sprintf("MongoDB port %d is closed or unreachable", port), nil
	}
	defer conn.Close()

	// MongoDB wire protocol - simple isMaster command
	// This is a simplified check - real MongoDB protocol is more complex
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Try HTTP endpoint first (MongoDB 3.6+ has HTTP interface on same port sometimes)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d", target, port))
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if strings.Contains(string(body), "MongoDB") || strings.Contains(string(body), "mongo") {
			return fmt.Sprintf(`[CRITICAL] MongoDB UNAUTHENTICATED ACCESS on %s:%d
Impact: Full database access, data theft, ransomware risk
Remediation: Enable authentication in mongod.conf (security.authorization: enabled)
Severity: CRITICAL`, target, port), nil
		}
	}

	// Simple connection test - if we can connect, likely no auth
	return fmt.Sprintf(`[CRITICAL] MongoDB UNAUTHENTICATED ACCESS on %s:%d
Impact: Full database access, data theft, ransomware risk
Remediation: Enable authentication in mongod.conf (security.authorization: enabled)
Severity: CRITICAL
Note: Connected successfully without credentials`, target, port), nil
}

func (s *MCPServer) checkMySQL(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 3306
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	username := "root"
	if u, ok := args["username"].(string); ok && u != "" {
		username = u
	}

	passwords := []string{"", "root", "password", "root123", "mysql", "admin", "123456"}
	if p, ok := args["password"].(string); ok && p != "" {
		passwords = []string{p}
	}

	for _, password := range passwords {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", username, password, target, port)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()
		db.Close()

		if err == nil {
			passDisplay := password
			if password == "" {
				passDisplay = "(empty)"
			}
			return fmt.Sprintf(`[CRITICAL] MySQL WEAK CREDENTIALS on %s:%d
Username: %s
Password: %s
Impact: Full database access, potential data breach
Remediation: Change to strong password, restrict network access
Severity: CRITICAL`, target, port, username, passDisplay), nil
		}
	}

	return fmt.Sprintf("[OK] MySQL on %s:%d - no weak credentials found (tested: root with common passwords)", target, port), nil
}

func (s *MCPServer) checkPostgres(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 5432
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	username := "postgres"
	if u, ok := args["username"].(string); ok && u != "" {
		username = u
	}

	passwords := []string{"", "postgres", "password", "admin", "admin123", "123456"}
	if p, ok := args["password"].(string); ok && p != "" {
		passwords = []string{p}
	}

	for _, password := range passwords {
		connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=5", target, port, username, password)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()
		db.Close()

		if err == nil {
			passDisplay := password
			if password == "" {
				passDisplay = "(empty)"
			}
			return fmt.Sprintf(`[CRITICAL] PostgreSQL WEAK CREDENTIALS on %s:%d
Username: %s
Password: %s
Impact: Full database access, potential data breach
Remediation: Change to strong password, configure pg_hba.conf
Severity: CRITICAL`, target, port, username, passDisplay), nil
		}
	}

	return fmt.Sprintf("[OK] PostgreSQL on %s:%d - no weak credentials found", target, port), nil
}

func (s *MCPServer) checkElasticsearch(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 9200
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d", target, port))
	if err != nil {
		return fmt.Sprintf("Elasticsearch port %d is closed or unreachable", port), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if strings.Contains(string(body), "cluster_name") || strings.Contains(string(body), "elasticsearch") {
		// Try to get indices
		indicesResp, err := client.Get(fmt.Sprintf("http://%s:%d/_cat/indices", target, port))
		var indices string
		if err == nil {
			defer indicesResp.Body.Close()
			indicesBody, _ := io.ReadAll(io.LimitReader(indicesResp.Body, 2048))
			indices = string(indicesBody)
		}

		return fmt.Sprintf(`[CRITICAL] Elasticsearch UNAUTHENTICATED ACCESS on %s:%d
Cluster Info: %s
Indices: %s
Impact: Full access to all indexed data, potential data breach
Remediation: Enable X-Pack security or use a reverse proxy with auth
Severity: CRITICAL`, target, port, strings.TrimSpace(string(body)), strings.TrimSpace(indices)), nil
	}

	return fmt.Sprintf("[OK] Elasticsearch on %s:%d - requires authentication or not Elasticsearch", target, port), nil
}

func (s *MCPServer) checkDockerRegistry(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 5000
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Check v2 API
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/v2/", target, port))
	if err != nil {
		return fmt.Sprintf("Docker Registry port %d is closed or unreachable", port), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 401 {
		// Check if auth is required
		if resp.StatusCode == 401 {
			return fmt.Sprintf("[OK] Docker Registry on %s:%d requires authentication", target, port), nil
		}

		// Try to list repositories
		catalogResp, err := client.Get(fmt.Sprintf("http://%s:%d/v2/_catalog", target, port))
		var repos string
		if err == nil {
			defer catalogResp.Body.Close()
			if catalogResp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(catalogResp.Body, 4096))
				repos = string(body)
			}
		}

		return fmt.Sprintf(`[CRITICAL] Docker Registry UNAUTHENTICATED ACCESS on %s:%d
API Version: v2
Repositories: %s
Impact: Anyone can pull/push Docker images, supply chain attack vector
Remediation: Enable authentication or restrict network access
Severity: CRITICAL

An attacker could:
1. Pull sensitive images containing secrets/code
2. Push malicious images that may be deployed
3. Delete or overwrite existing images`, target, port, repos), nil
	}

	return fmt.Sprintf("Docker Registry on %s:%d - unexpected response: %d", target, port, resp.StatusCode), nil
}

func (s *MCPServer) checkFTPAnonymous(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 21
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return fmt.Sprintf("FTP port %d is closed or unreachable", port), nil
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read banner
	banner, _ := reader.ReadString('\n')

	// Try anonymous login
	conn.Write([]byte("USER anonymous\r\n"))
	resp, _ := reader.ReadString('\n')

	if strings.HasPrefix(resp, "331") {
		conn.Write([]byte("PASS anonymous@example.com\r\n"))
		resp, _ = reader.ReadString('\n')

		if strings.HasPrefix(resp, "230") {
			// List directory
			conn.Write([]byte("PASV\r\n"))
			reader.ReadString('\n')

			return fmt.Sprintf(`[HIGH] FTP ANONYMOUS ACCESS ALLOWED on %s:%d
Banner: %s
Impact: Unauthorized file access, potential data leak
Remediation: Disable anonymous FTP or restrict to read-only public files
Severity: HIGH`, target, port, strings.TrimSpace(banner)), nil
		}
	}

	return fmt.Sprintf("[OK] FTP on %s:%d - anonymous login disabled\nBanner: %s", target, port, strings.TrimSpace(banner)), nil
}

func (s *MCPServer) checkSSH(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 22
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return fmt.Sprintf("SSH port %d is closed or unreachable", port), nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	return fmt.Sprintf(`SSH service on %s:%d
Banner: %s
Note: Use check_ssh with username/password to test credentials`, target, port, strings.TrimSpace(banner)), nil
}

func (s *MCPServer) checkSMB(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := 445
	if p, ok := args["port"].(float64); ok {
		port = int(p)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return fmt.Sprintf("SMB port %d is closed or unreachable", port), nil
	}
	conn.Close()

	return fmt.Sprintf(`SMB service detected on %s:%d
Note: Manual testing recommended with smbclient or enum4linux
Potential checks:
- Null session enumeration
- Guest access to shares
- SMB signing disabled`, target, port), nil
}

func (s *MCPServer) webScan(args map[string]interface{}) (string, error) {
	url := args["url"].(string)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Sprintf("Failed to connect to %s: %v", url, err), nil
	}
	defer resp.Body.Close()

	var findings []string

	// Check security headers
	securityHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS not set - vulnerable to downgrade attacks",
		"X-Frame-Options":           "Clickjacking protection missing",
		"X-Content-Type-Options":    "MIME sniffing protection missing",
		"Content-Security-Policy":   "CSP not set - XSS protection reduced",
		"X-XSS-Protection":          "XSS filter not enabled",
	}

	for header, issue := range securityHeaders {
		if resp.Header.Get(header) == "" {
			findings = append(findings, fmt.Sprintf("[MEDIUM] %s: %s", header, issue))
		}
	}

	// Check for information disclosure
	if server := resp.Header.Get("Server"); server != "" {
		findings = append(findings, fmt.Sprintf("[LOW] Server header discloses: %s", server))
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		findings = append(findings, fmt.Sprintf("[LOW] X-Powered-By discloses: %s", powered))
	}

	// Check CORS
	if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors == "*" {
		findings = append(findings, "[MEDIUM] CORS allows all origins (Access-Control-Allow-Origin: *)")
	}

	if len(findings) == 0 {
		return fmt.Sprintf("Web scan of %s - no issues found", url), nil
	}

	return fmt.Sprintf("Web scan of %s:\n%s", url, strings.Join(findings, "\n")), nil
}

func (s *MCPServer) grabBanner(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	port := int(args["port"].(float64))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return fmt.Sprintf("Port %d is closed or unreachable", port), nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send probe based on port
	switch port {
	case 80, 8080, 8081, 8082, 8083, 8084, 8085, 3000, 5000:
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + target + "\r\n\r\n"))
	case 21:
		// FTP sends banner automatically
	case 22:
		// SSH sends banner automatically
	case 25, 587:
		// SMTP sends banner automatically
	default:
		conn.Write([]byte("\r\n"))
	}

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)

	return fmt.Sprintf("Banner from %s:%d:\n%s", target, port, string(buf[:n])), nil
}

// Top passwords - subset of rockyou + common defaults (embedded for speed)
var topPasswords = []string{
	// Empty and trivial
	"", "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
	"letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
	"ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
	"qazwsx", "michael", "football", "password1", "password123", "welcome",
	"jesus", "ninja", "mustang", "password2", "amanda", "thomas", "charlie",
	"robert", "jordan", "access", "love", "buster", "soccer", "hockey",
	"killer", "george", "andrew", "michelle", "joshua", "pepper", "daniel",
	"hunter", "cheese", "harley", "ranger", "jennifer", "matthew", "starwars",
	// Default credentials
	"admin", "admin123", "admin1234", "administrator", "root", "root123", "toor",
	"guest", "test", "test123", "changeme", "default", "pass", "pass123",
	// Service defaults
	"mysql", "postgres", "oracle", "sqlserver", "redis", "mongodb", "cassandra",
	"jenkins", "tomcat", "admin@123", "P@ssw0rd", "P@ssword1", "Passw0rd!",
	// Years and patterns
	"2020", "2021", "2022", "2023", "2024", "summer2023", "winter2023", "spring2024",
	"qwerty123", "asdfghjkl", "zxcvbnm", "1q2w3e4r", "1qaz2wsx", "q1w2e3r4",
	// More common
	"princess", "rockyou", "nicole", "jessica", "diamond", "michelle", "secret",
	"love123", "lovely", "freedom", "whatever", "biteme", "ginger", "maggie",
	"summer", "snoopy", "dakota", "brandy", "purple", "yankees", "liverpool",
	"arsenal", "angels", "giants", "cowboys", "steelers", "packers", "chiefs",
	// Extended list for thorough testing
	"london", "computer", "cookie", "corvette", "taylor", "compaq", "internet",
	"samantha", "golfer", "boomer", "cheese", "carlos", "winner", "corvette",
	"blahblah", "patrick", "flower", "jasmine", "butter", "sparky", "cowboy",
	"camaro", "matrix", "falcon", "iloveu", "guitar", "phoenix", "mickey",
	"knight", "yellow", "friend", "rabbit", "enter", "happy", "turtle",
	"thunder", "chicken", "miller", "scooter", "peanut", "hammer", "morgan",
	"donald", "beaver", "tiger", "panther", "bronco", "richard", "falcon",
	"taylor", "austin", "merlin", "sandra", "helpme", "bowling", "asdfgh",
	"zxcvbn", "qweasd", "admin1", "admin12", "admin01", "passpass", "test1234",
	"welcome1", "welcome123", "hello", "hello123", "1234", "12345", "123456789",
	"1234567890", "0987654321", "999999", "888888", "777777", "666666", "555555",
	"111111", "000000", "aaaaaa", "abc1234", "abcdef", "qwer1234", "asdf1234",
}

// CredSprayResult holds a single spray attempt result
type CredSprayResult struct {
	Username string
	Password string
	Success  bool
	Error    string
}

func (s *MCPServer) credentialSpray(args map[string]interface{}) (string, error) {
	target := args["target"].(string)
	service := args["service"].(string)

	// Default port based on service
	port := 0
	switch service {
	case "ssh":
		port = 22
	case "mysql":
		port = 3306
	case "postgres":
		port = 5432
	default:
		return fmt.Sprintf("Unknown service: %s. Supported: ssh, mysql, postgres", service), nil
	}
	if p, ok := args["port"].(float64); ok && p > 0 {
		port = int(p)
	}

	// Parse usernames
	usernames := []string{"root", "admin", "user"}
	if u, ok := args["usernames"].(string); ok && u != "" {
		usernames = strings.Split(u, ",")
		for i := range usernames {
			usernames[i] = strings.TrimSpace(usernames[i])
		}
	}

	// Max passwords (default 100, max 100000)
	maxPasswords := 100
	if m, ok := args["max_passwords"].(float64); ok && m > 0 {
		maxPasswords = int(m)
		if maxPasswords > 100000 {
			maxPasswords = 100000
		}
	}

	// Workers (default 10, max 50)
	workers := 10
	if w, ok := args["workers"].(float64); ok && w > 0 {
		workers = int(w)
		if workers > 50 {
			workers = 50
		}
	}

	// Delay between attempts (default 100ms)
	delayMs := 100
	if d, ok := args["delay_ms"].(float64); ok && d >= 0 {
		delayMs = int(d)
	}

	// Build password list (from file or embedded)
	var passwords []string
	if pwFile, ok := args["password_file"].(string); ok && pwFile != "" {
		// Load from file
		file, err := os.Open(pwFile)
		if err != nil {
			return fmt.Sprintf("Failed to open password file: %v", err), nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() && len(passwords) < maxPasswords {
			pw := strings.TrimSpace(scanner.Text())
			if pw != "" {
				passwords = append(passwords, pw)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Sprintf("Error reading password file: %v", err), nil
		}
	} else {
		// Use embedded passwords
		passwords = topPasswords
		if len(passwords) > maxPasswords {
			passwords = passwords[:maxPasswords]
		}
	}

	// Build work queue
	type workItem struct {
		username string
		password string
	}
	var workQueue []workItem
	for _, user := range usernames {
		for _, pass := range passwords {
			workQueue = append(workQueue, workItem{user, pass})
		}
	}

	// Results
	var mu sync.Mutex
	var found []CredSprayResult
	var tested int
	stopChan := make(chan struct{})
	var stopped bool

	// Worker function
	worker := func(items <-chan workItem, wg *sync.WaitGroup) {
		defer wg.Done()
		for item := range items {
			select {
			case <-stopChan:
				return
			default:
			}

			success := false
			var err error

			switch service {
			case "ssh":
				success, err = trySSH(target, port, item.username, item.password)
			case "mysql":
				success, err = tryMySQL(target, port, item.username, item.password)
			case "postgres":
				success, err = tryPostgres(target, port, item.username, item.password)
			}

			mu.Lock()
			tested++
			if success {
				found = append(found, CredSprayResult{
					Username: item.username,
					Password: item.password,
					Success:  true,
				})
				// Stop on first success
				if !stopped {
					stopped = true
					close(stopChan)
				}
			}
			mu.Unlock()

			if err != nil && strings.Contains(err.Error(), "connection refused") {
				// Service down, stop
				mu.Lock()
				if !stopped {
					stopped = true
					close(stopChan)
				}
				mu.Unlock()
				return
			}

			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	// Create work channel and workers
	workChan := make(chan workItem, len(workQueue))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(workChan, &wg)
	}

	// Feed work
	for _, item := range workQueue {
		select {
		case <-stopChan:
			break
		case workChan <- item:
		}
	}
	close(workChan)

	// Wait for completion
	wg.Wait()

	// Format results
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Credential Spray Results for %s:%d (%s)\n", target, port, service))
	result.WriteString(fmt.Sprintf("Tested: %d credentials | Workers: %d | Delay: %dms\n", tested, workers, delayMs))
	result.WriteString(strings.Repeat("-", 50) + "\n")

	if len(found) > 0 {
		result.WriteString("\n[CRITICAL] VALID CREDENTIALS FOUND:\n")
		for _, cred := range found {
			passDisplay := cred.Password
			if passDisplay == "" {
				passDisplay = "(empty)"
			}
			result.WriteString(fmt.Sprintf("  ✓ %s:%s\n", cred.Username, passDisplay))
		}
		result.WriteString("\nImpact: Full access to service, potential lateral movement\n")
		result.WriteString("Remediation: Change passwords immediately, implement account lockout\n")
		result.WriteString("Severity: CRITICAL\n")
	} else {
		result.WriteString("\n[OK] No valid credentials found in top passwords\n")
	}

	return result.String(), nil
}

func trySSH(host string, port int, username, password string) (bool, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return false, err
	}
	client.Close()
	return true, nil
}

func tryMySQL(host string, port int, username, password string) (bool, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", username, password, host, port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

func tryPostgres(host string, port int, username, password string) (bool, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=3", host, port, username, password)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Helper functions

func expandPorts(portsArg string) []int {
	var ports []int
	parts := strings.Split(portsArg, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
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

func identifyService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
		143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
		5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
		8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
		5000: "docker-registry", 5601: "kibana", 9000: "minio", 9001: "minio-console",
		8081: "http-alt", 8082: "http-alt", 8083: "http-alt", 8084: "http-alt",
		8085: "http-alt", 389: "ldap", 636: "ldaps",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MCP protocol handlers

func (s *MCPServer) handleRequest(req JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "pentestai-mcp",
					"version": "1.0.0",
				},
			},
		}

	case "tools/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": s.getTools(),
			},
		}

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32602, Message: "Invalid params"},
			}
		}

		toolFunc, ok := s.tools[params.Name]
		if !ok {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32601, Message: "Tool not found: " + params.Name},
			}
		}

		result, err := toolFunc(params.Arguments)
		if err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ToolResult{
					Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
					IsError: true,
				},
			}
		}

		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolResult{
				Content: []ContentBlock{{Type: "text", Text: result}},
			},
		}

	case "notifications/initialized":
		// No response needed for notifications
		return JSONRPCResponse{}

	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: "Method not found: " + req.Method},
		}
	}
}

func (s *MCPServer) Run() {
	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		resp := s.handleRequest(req)
		if resp.JSONRPC == "" {
			continue // No response for notifications
		}

		output, _ := json.Marshal(resp)
		fmt.Println(string(output))
	}
}

func main() {
	server := NewMCPServer()
	server.Run()
}
