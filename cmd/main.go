package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"q/cmd/console"
	"q/cmd/server"
)

var version = "1.0.0"

func main() {
	var (
		showVersion = flag.Bool("version", false, "Show version")
		showHelp    = flag.Bool("help", false, "Show help")
		serverMode  = flag.Bool("server", false, "Run as HTTP API server")
		serverPort  = flag.String("port", "8081", "Port for HTTP server")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("Q v%s\n", version)
		os.Exit(0)
	}

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	// Load .env file if present
	loadEnvFile(".env")
	loadEnvFile("/opt/.env") // Also check /opt/.env on server

	// Check for required tools/permissions
	checkRequirements()

	if *serverMode {
		// Start HTTP API server
		s := server.NewServer(*serverPort)
		s.Run()
	} else {
		// Start interactive console
		c := console.NewConsole()
		c.Run()
	}
}

func printHelp() {
	help := `
Q - AI-Powered Penetration Testing Toolkit

Usage:
  q [options]

Options:
  --help       Show this help message
  --version    Show version information
  --server     Run as HTTP API server
  --port       Port for HTTP server (default: 8081)

Environment Variables:
  ANTHROPIC_API_KEY    API key for Claude AI integration
  NVD_API_KEY          API key for NVD vulnerability lookups (increases rate limits)
  TLS_ENABLED          Set to "true" to enable HTTPS (auto-generates self-signed cert)
  TLS_CERT             Path to TLS certificate file (default: /opt/data/certs/server.crt)
  TLS_KEY              Path to TLS private key file (default: /opt/data/certs/server.key)

Examples:
  q                     Start interactive console
  q --server            Start HTTP API server on port 8081
  q --server --port 9000  Start API on port 9000

  # Enable HTTPS with auto-generated self-signed certificate:
  TLS_ENABLED=true q --server --port 443

  # Use custom certificates:
  TLS_ENABLED=true TLS_CERT=/path/cert.pem TLS_KEY=/path/key.pem q --server

API Endpoints (server mode):
  POST /api/scan         - Start a scan (async)
  GET  /api/scan/{id}    - Get scan status/results
  POST /api/recon        - Quick port scan
  POST /api/web-scan     - Web vulnerability scan
  POST /api/exploit      - Run exploit module
  POST /api/ai-analyze   - AI analysis of results
  GET  /api/cve          - CVE lookup (NVD + Exploit-DB)
  POST /api/vuln-search  - Search vulnerabilities by product/service
  GET  /api/health       - Health check

IMPORTANT: Only use this tool on systems you have authorization to test.
`
	fmt.Print(help)
}

func checkRequirements() {
	// Check for API key (optional but recommended)
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		fmt.Println("[!] ANTHROPIC_API_KEY not set - AI features will be disabled")
	}
}

// loadEnvFile loads environment variables from a file
func loadEnvFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		return // File doesn't exist, that's ok
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			value = strings.Trim(value, "\"'")
			os.Setenv(key, value)
		}
	}
}
