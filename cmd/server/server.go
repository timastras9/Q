package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"pentestai/internal/ai"
	"pentestai/internal/exploit"
	"pentestai/internal/recon"
	"pentestai/internal/report"
	"pentestai/internal/storage"
	"pentestai/internal/webapp"
)

type Server struct {
	port       string
	tlsEnabled bool
	certFile   string
	keyFile    string
	scanner    *recon.Scanner
	webScanner *webapp.WebScanner
	framework  *exploit.Framework
	aiClient   *ai.ClaudeClient
	store      *storage.Store
	scans      map[string]*ScanJob
	scansMu    sync.RWMutex
}

type ScanJob struct {
	ID        string      `json:"id"`
	Target    string      `json:"target"`
	Type      string      `json:"type"`
	Status    string      `json:"status"`
	StartTime time.Time   `json:"start_time"`
	EndTime   *time.Time  `json:"end_time,omitempty"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type ScanRequest struct {
	Target   string   `json:"target"`
	Type     string   `json:"type"` // recon, web, exploit, full, autopwn
	Options  []string `json:"options,omitempty"`
}

type ScanResponse struct {
	Success bool        `json:"success"`
	JobID   string      `json:"job_id,omitempty"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func NewServer(port string) *Server {
	s := &Server{
		port:       port,
		tlsEnabled: os.Getenv("TLS_ENABLED") == "true" || os.Getenv("TLS_ENABLED") == "1",
		certFile:   os.Getenv("TLS_CERT"),
		keyFile:    os.Getenv("TLS_KEY"),
		scanner:    recon.NewScanner(),
		webScanner: webapp.NewWebScanner(),
		framework:  exploit.NewFramework(),
		scans:      make(map[string]*ScanJob),
	}

	// Default cert paths if TLS enabled but paths not specified
	if s.tlsEnabled && s.certFile == "" {
		s.certFile = "/opt/data/certs/server.crt"
		s.keyFile = "/opt/data/certs/server.key"
	}

	// Initialize AI client if API key is available
	if client, err := ai.NewClaudeClient(); err == nil {
		s.aiClient = client
	}

	// Initialize database storage
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/opt/data/nsicorp.db"
	}
	if store, err := storage.NewStore(dbPath); err == nil {
		s.store = store
		log.Printf("[*] Database connected: %s", dbPath)
	} else {
		log.Printf("[!] Database connection failed: %v", err)
	}

	return s
}

func (s *Server) Run() {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/scan", s.corsMiddleware(s.handleScan))
	mux.HandleFunc("/api/scan/", s.corsMiddleware(s.handleScanStatus))
	mux.HandleFunc("/api/scans", s.corsMiddleware(s.handleListScans))
	mux.HandleFunc("/api/report/", s.corsMiddleware(s.handleReport))
	mux.HandleFunc("/api/recon", s.corsMiddleware(s.handleRecon))
	mux.HandleFunc("/api/web-scan", s.corsMiddleware(s.handleWebScan))
	mux.HandleFunc("/api/exploit", s.corsMiddleware(s.handleExploit))
	mux.HandleFunc("/api/ai-analyze", s.corsMiddleware(s.handleAIAnalyze))
	mux.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))

	protocol := "http"
	if s.tlsEnabled {
		protocol = "https"
	}

	log.Printf("[*] PentestAI API server starting on %s://0.0.0.0:%s", protocol, s.port)
	log.Printf("[*] Endpoints:")
	log.Printf("    POST /api/scan        - Start a scan")
	log.Printf("    GET  /api/scan/{id}   - Get scan status/results")
	log.Printf("    GET  /api/scans       - List all scans")
	log.Printf("    GET  /api/report/{id} - Get report (JSON/HTML/PDF)")
	log.Printf("    POST /api/recon       - Quick recon scan")
	log.Printf("    POST /api/web-scan    - Web vulnerability scan")
	log.Printf("    POST /api/exploit     - Run exploits")
	log.Printf("    POST /api/ai-analyze  - AI analysis")
	log.Printf("    GET  /api/health      - Health check")

	if s.tlsEnabled {
		// Ensure certificates exist
		if err := s.ensureCertificates(); err != nil {
			log.Fatalf("Failed to setup TLS certificates: %v", err)
		}

		// Configure TLS
		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		server := &http.Server{
			Addr:      ":" + s.port,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		log.Printf("[*] TLS enabled with cert: %s", s.certFile)
		if err := server.ListenAndServeTLS(s.certFile, s.keyFile); err != nil {
			log.Fatalf("TLS Server failed: %v", err)
		}
	} else {
		if err := http.ListenAndServe(":"+s.port, mux); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// ensureCertificates checks if TLS certs exist, generates self-signed if not
func (s *Server) ensureCertificates() error {
	// Check if certificates already exist
	if _, err := os.Stat(s.certFile); err == nil {
		if _, err := os.Stat(s.keyFile); err == nil {
			log.Printf("[*] Using existing certificates")
			return nil
		}
	}

	log.Printf("[*] Generating self-signed TLS certificate...")

	// Create directory if needed
	certDir := strings.TrimSuffix(s.certFile, "/server.crt")
	if certDir != s.certFile {
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return fmt.Errorf("failed to create cert directory: %v", err)
		}
	}

	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"PentestAI"},
			CommonName:   "PentestAI API Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "pentestai", "api.pentestai.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Write certificate to file
	certOut, err := os.Create(s.certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		return fmt.Errorf("failed to write cert: %v", err)
	}
	certOut.Close()

	// Write private key to file
	keyOut, err := os.OpenFile(s.keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		keyOut.Close()
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		keyOut.Close()
		return fmt.Errorf("failed to write key: %v", err)
	}
	keyOut.Close()

	log.Printf("[*] Generated self-signed certificate: %s", s.certFile)
	log.Printf("[*] Generated private key: %s", s.keyFile)
	log.Printf("[!] WARNING: Self-signed certificate - clients should use -k or --insecure flag")

	return nil
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, ScanResponse{
		Success: true,
		Message: "PentestAI API is running",
		Data: map[string]interface{}{
			"version":    "1.0.0",
			"ai_enabled": s.aiClient != nil,
		},
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		s.errorResponse(w, "Target is required", http.StatusBadRequest)
		return
	}

	// Validate target (basic security check)
	if !isValidTarget(req.Target) {
		s.errorResponse(w, "Invalid target format", http.StatusBadRequest)
		return
	}

	// Create job
	jobID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
	job := &ScanJob{
		ID:        jobID,
		Target:    req.Target,
		Type:      req.Type,
		Status:    "running",
		StartTime: time.Now(),
	}

	s.scansMu.Lock()
	s.scans[jobID] = job
	s.scansMu.Unlock()

	// Run scan in background
	go s.runScan(job, req)

	s.jsonResponse(w, ScanResponse{
		Success: true,
		JobID:   jobID,
		Message: "Scan started",
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	jobID := strings.TrimSuffix(path, "/")

	s.scansMu.RLock()
	job, exists := s.scans[jobID]
	s.scansMu.RUnlock()

	if !exists {
		s.errorResponse(w, "Scan not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, ScanResponse{
		Success: true,
		Data:    job,
	})
}

func (s *Server) handleRecon(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !isValidTarget(req.Target) {
		s.errorResponse(w, "Invalid target", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	host, err := s.scanner.FastFullScan(ctx, req.Target)
	if err != nil {
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, ScanResponse{
		Success: true,
		Data:    host,
	})
}

func (s *Server) handleWebScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Ensure target is a URL
	target := req.Target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	results, err := s.webScanner.Scan(ctx, target)
	if err != nil {
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, ScanResponse{
		Success: true,
		Data:    results,
	})
}

func (s *Server) handleExploit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target   string `json:"target"`
		Exploit  string `json:"exploit"`
		Options  map[string]string `json:"options"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Target == "" || req.Exploit == "" {
		s.errorResponse(w, "Target and exploit are required", http.StatusBadRequest)
		return
	}

	// Use the exploit framework
	if err := s.framework.Use(req.Exploit); err != nil {
		s.errorResponse(w, fmt.Sprintf("Exploit not found: %s", req.Exploit), http.StatusNotFound)
		return
	}

	// Set options
	current := s.framework.Current()
	if current == nil {
		s.errorResponse(w, "Failed to load exploit", http.StatusInternalServerError)
		return
	}

	// Set RHOST
	current.SetOption("RHOST", req.Target)
	for key, val := range req.Options {
		current.SetOption(key, val)
	}

	// Run exploit
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := s.framework.Run(ctx)
	if err != nil {
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, ScanResponse{
		Success: result.Success,
		Data:    result,
	})
}

func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		s.errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.aiClient == nil {
		s.errorResponse(w, "AI features not available", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Data   interface{} `json:"data"`
		Prompt string      `json:"prompt"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Convert data to JSON string for analysis
	dataJSON, _ := json.MarshalIndent(req.Data, "", "  ")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	decision, err := s.aiClient.Analyze(ctx, string(dataJSON))
	if err != nil {
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, ScanResponse{
		Success: true,
		Data:    decision,
	})
}

func (s *Server) runScan(job *ScanJob, req ScanRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var result interface{}
	var err error

	switch req.Type {
	case "recon", "":
		result, err = s.scanner.FastFullScan(ctx, req.Target)
	case "web":
		target := req.Target
		if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}
		result, err = s.webScanner.Scan(ctx, target)
	case "full", "autopwn":
		result, err = s.runFullScan(ctx, req.Target)
	default:
		err = fmt.Errorf("unknown scan type: %s", req.Type)
	}

	now := time.Now()
	s.scansMu.Lock()
	job.EndTime = &now
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
	} else {
		job.Status = "completed"
		job.Result = result
	}
	s.scansMu.Unlock()

	// Save to database if storage is available
	if s.store != nil {
		resultJSON, _ := json.Marshal(result)
		record := &storage.ScanRecord{
			ID:        job.ID,
			Status:    job.Status,
			Targets:   job.Target,
			StartTime: job.StartTime,
			EndTime:   &now,
			CreatedAt: job.StartTime,
		}

		// Store results based on scan type
		switch req.Type {
		case "recon", "":
			record.Recon = resultJSON
		case "web":
			record.Vulnerabilities = resultJSON
		default:
			record.Recon = resultJSON
		}

		if err := s.store.SaveScan(record); err != nil {
			log.Printf("[!] Failed to save scan to database: %v", err)
		}
	}
}

func (s *Server) runFullScan(ctx context.Context, target string) (interface{}, error) {
	results := make(map[string]interface{})

	// Recon scan
	host, err := s.scanner.FastFullScan(ctx, target)
	if err != nil {
		return nil, err
	}
	results["recon"] = host

	// Web scan if HTTP ports found
	webTarget := target
	for _, port := range host.Ports {
		if port.Service.Name == "http" || port.Service.Name == "https" {
			if port.Number == 443 || port.Service.Name == "https" {
				webTarget = fmt.Sprintf("https://%s", target)
			} else if port.Number == 80 {
				webTarget = fmt.Sprintf("http://%s", target)
			} else {
				webTarget = fmt.Sprintf("http://%s:%d", target, port.Number)
			}
			break
		}
	}

	webResults, err := s.webScanner.Scan(ctx, webTarget)
	if err == nil {
		results["web"] = webResults
	}

	// AI analysis if available
	if s.aiClient != nil {
		dataJSON, _ := json.Marshal(results)
		decision, err := s.aiClient.Analyze(ctx, string(dataJSON))
		if err == nil {
			results["ai_analysis"] = decision
		}
	}

	return results, nil
}

func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) errorResponse(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ScanResponse{
		Success: false,
		Message: message,
	})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		s.errorResponse(w, "Database not available", http.StatusServiceUnavailable)
		return
	}

	scans, err := s.store.ListScans(50)
	if err != nil {
		s.errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, ScanResponse{
		Success: true,
		Data:    scans,
	})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		s.errorResponse(w, "Database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract scan ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/report/")
	scanID := strings.TrimSuffix(path, "/")

	// Check for format parameter (json, html, pdf)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Get scan from database
	scan, err := s.store.GetScan(scanID)
	if err != nil {
		s.errorResponse(w, "Scan not found", http.StatusNotFound)
		return
	}

	// Build report from stored data
	rpt := report.NewReport("Penetration Test Report", scan.Targets)
	rpt.EndTime = time.Now()
	if scan.EndTime != nil {
		rpt.EndTime = *scan.EndTime
	}

	// Parse vulnerabilities from JSON
	if len(scan.Vulnerabilities) > 0 {
		var vulns []struct {
			Type        string `json:"type"`
			Severity    string `json:"severity"`
			Target      string `json:"target"`
			Description string `json:"description"`
			Evidence    string `json:"evidence,omitempty"`
			Remediation string `json:"remediation,omitempty"`
		}
		if err := json.Unmarshal(scan.Vulnerabilities, &vulns); err == nil {
			for _, v := range vulns {
				rpt.AddWebFinding(webapp.Finding{
					Type:        v.Type,
					Severity:    v.Severity,
					URL:         v.Target,
					Description: v.Description,
					Evidence:    v.Evidence,
					Remediation: v.Remediation,
				})
			}
		}
	}

	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(rpt.ToHTML()))
	case "pdf":
		// Return PDF export data (to be rendered by client)
		w.Header().Set("Content-Type", "application/json")
		pdfData := rpt.ToPDFExport()
		json.NewEncoder(w).Encode(pdfData)
	case "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write([]byte(rpt.ToMarkdown()))
	default:
		// Return full scan data as JSON
		s.jsonResponse(w, ScanResponse{
			Success: true,
			Data:    scan,
		})
	}
}

func isValidTarget(target string) bool {
	// Basic validation - prevent obvious injection attempts
	if target == "" {
		return false
	}
	if len(target) > 255 {
		return false
	}
	// Block obvious dangerous patterns
	dangerous := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\\"}
	for _, d := range dangerous {
		if strings.Contains(target, d) {
			return false
		}
	}
	return true
}
