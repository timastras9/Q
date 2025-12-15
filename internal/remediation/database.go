package remediation

import (
	"fmt"
	"sort"
	"strings"
)

// Severity levels matching CVSS
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	return [...]string{"Informational", "Low", "Medium", "High", "Critical"}[s]
}

func (s Severity) CVSSRange() string {
	return [...]string{"0.0", "0.1-3.9", "4.0-6.9", "7.0-8.9", "9.0-10.0"}[s]
}

// Priority for remediation
type Priority int

const (
	PriorityLow Priority = iota
	PriorityMedium
	PriorityHigh
	PriorityCritical
)

func (p Priority) String() string {
	return [...]string{"Low", "Medium", "High", "Critical"}[p]
}

// Recommendation contains remediation guidance
type Recommendation struct {
	VulnType       string            `json:"vuln_type"`
	Title          string            `json:"title"`
	Severity       Severity          `json:"severity"`
	Priority       Priority          `json:"priority"`
	Description    string            `json:"description"`
	Impact         string            `json:"impact"`
	Remediation    string            `json:"remediation"`
	QuickFix       string            `json:"quick_fix,omitempty"`
	LongTermFix    string            `json:"long_term_fix,omitempty"`
	References     []string          `json:"references"`
	CWE            []string          `json:"cwe"`
	OWASP          []string          `json:"owasp"`
	Compliance     []string          `json:"compliance,omitempty"`
	TestingSteps   []string          `json:"testing_steps,omitempty"`
	CodeExamples   map[string]string `json:"code_examples,omitempty"`
	EffortEstimate string            `json:"effort_estimate"`
}

// Database holds all remediation recommendations
type Database struct {
	recommendations map[string]*Recommendation
}

// NewDatabase creates and initializes the remediation database
func NewDatabase() *Database {
	db := &Database{
		recommendations: make(map[string]*Recommendation),
	}
	db.loadRecommendations()
	return db
}

// Get returns a recommendation by vulnerability type
func (db *Database) Get(vulnType string) *Recommendation {
	key := strings.ToLower(strings.ReplaceAll(vulnType, " ", "_"))
	if rec, ok := db.recommendations[key]; ok {
		return rec
	}
	// Try partial match
	for k, rec := range db.recommendations {
		if strings.Contains(key, k) || strings.Contains(k, key) {
			return rec
		}
	}
	return nil
}

// GetBySeverity returns all recommendations of a given severity or higher
func (db *Database) GetBySeverity(minSeverity Severity) []*Recommendation {
	var result []*Recommendation
	for _, rec := range db.recommendations {
		if rec.Severity >= minSeverity {
			result = append(result, rec)
		}
	}
	// Sort by severity (highest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Severity > result[j].Severity
	})
	return result
}

// GetAll returns all recommendations
func (db *Database) GetAll() []*Recommendation {
	result := make([]*Recommendation, 0, len(db.recommendations))
	for _, rec := range db.recommendations {
		result = append(result, rec)
	}
	return result
}

// loadRecommendations populates the database with remediation guidance
func (db *Database) loadRecommendations() {
	// SQL Injection
	db.recommendations["sql_injection"] = &Recommendation{
		VulnType:    "SQL Injection",
		Title:       "SQL Injection Vulnerability",
		Severity:    SeverityCritical,
		Priority:    PriorityCritical,
		Description: "SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.",
		Impact:      "Complete database compromise, data theft, data manipulation, authentication bypass, and in some cases, operating system command execution.",
		Remediation: `1. Use parameterized queries (prepared statements) for all database operations
2. Use stored procedures with parameterized inputs
3. Implement input validation with allowlists
4. Apply principle of least privilege to database accounts
5. Escape all user-supplied input (as a secondary defense)`,
		QuickFix: "Replace dynamic SQL queries with parameterized queries immediately.",
		LongTermFix: `1. Implement an ORM (Object-Relational Mapping) framework
2. Conduct code review for all database interactions
3. Implement Web Application Firewall (WAF) rules
4. Regular security testing and code audits`,
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
		CWE:        []string{"CWE-89", "CWE-564"},
		OWASP:      []string{"A03:2021 - Injection"},
		Compliance: []string{"PCI-DSS 6.5.1", "HIPAA", "SOC 2"},
		TestingSteps: []string{
			"Test all input fields with SQL metacharacters",
			"Use automated scanners like SQLMap",
			"Review code for dynamic query construction",
			"Test stored procedures for injection points",
		},
		CodeExamples: map[string]string{
			"python_vulnerable": `# VULNERABLE - Do not use
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)`,
			"python_secure": `# SECURE - Use parameterized queries
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))`,
			"java_vulnerable": `// VULNERABLE - Do not use
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
stmt.executeQuery(query);`,
			"java_secure": `// SECURE - Use PreparedStatement
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, userId);
pstmt.executeQuery();`,
			"go_secure": `// SECURE - Use parameterized queries
query := "SELECT * FROM users WHERE id = $1"
rows, err := db.Query(query, userID)`,
		},
		EffortEstimate: "Medium - 2-5 days depending on codebase size",
	}

	// Cross-Site Scripting (XSS)
	db.recommendations["xss"] = &Recommendation{
		VulnType:    "Cross-Site Scripting",
		Title:       "Cross-Site Scripting (XSS) Vulnerability",
		Severity:    SeverityHigh,
		Priority:    PriorityHigh,
		Description: "XSS attacks occur when an application includes untrusted data in a web page without proper validation or escaping. This allows attackers to execute scripts in the victim's browser.",
		Impact:      "Session hijacking, credential theft, defacement, malware distribution, and phishing attacks.",
		Remediation: `1. Encode output based on context (HTML, JavaScript, URL, CSS)
2. Use Content Security Policy (CSP) headers
3. Implement input validation with allowlists
4. Use HTTPOnly and Secure flags on cookies
5. Use modern frameworks with auto-escaping`,
		QuickFix: "Enable output encoding in your template engine and add basic CSP headers.",
		LongTermFix: `1. Implement strict Content Security Policy
2. Migrate to a framework with automatic output encoding
3. Use DOM-based XSS prevention techniques
4. Regular security scanning of all user inputs`,
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		},
		CWE:        []string{"CWE-79"},
		OWASP:      []string{"A03:2021 - Injection"},
		Compliance: []string{"PCI-DSS 6.5.7", "SOC 2"},
		CodeExamples: map[string]string{
			"csp_header": `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`,
			"html_encoding": `// JavaScript - encode before inserting into HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}`,
		},
		EffortEstimate: "Medium - 3-7 days for comprehensive fix",
	}

	// Default/Weak Credentials
	db.recommendations["default_credentials"] = &Recommendation{
		VulnType:    "Default Credentials",
		Title:       "Default or Weak Credentials",
		Severity:    SeverityCritical,
		Priority:    PriorityCritical,
		Description: "The system uses default, weak, or easily guessable credentials that can be exploited by attackers to gain unauthorized access.",
		Impact:      "Complete system compromise, unauthorized access to sensitive data, lateral movement within the network.",
		Remediation: `1. Change all default credentials immediately
2. Implement strong password policy (min 12 chars, complexity)
3. Use multi-factor authentication (MFA)
4. Implement account lockout policies
5. Use password managers for credential storage`,
		QuickFix:    "Change default passwords to strong, unique passwords immediately.",
		LongTermFix: "Implement centralized identity management with MFA and regular credential rotation.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
		},
		CWE:        []string{"CWE-521", "CWE-798"},
		OWASP:      []string{"A07:2021 - Identification and Authentication Failures"},
		Compliance: []string{"PCI-DSS 8.2", "NIST 800-53 IA-5", "HIPAA"},
		TestingSteps: []string{
			"Test all login interfaces with default credentials",
			"Check vendor documentation for default accounts",
			"Use credential stuffing with common password lists",
			"Review configuration files for hardcoded credentials",
		},
		EffortEstimate: "Low - 1-2 hours for immediate fix",
	}

	// SSH Weak Configuration
	db.recommendations["ssh_weak_config"] = &Recommendation{
		VulnType:    "SSH Misconfiguration",
		Title:       "SSH Weak Configuration",
		Severity:    SeverityMedium,
		Priority:    PriorityMedium,
		Description: "SSH service is configured with weak settings that could allow unauthorized access or man-in-the-middle attacks.",
		Impact:      "Unauthorized remote access, credential theft, session hijacking.",
		Remediation: `1. Disable password authentication, use key-based only
2. Disable root login (PermitRootLogin no)
3. Use strong key exchange algorithms
4. Implement fail2ban or similar
5. Change default SSH port (security through obscurity, secondary measure)`,
		QuickFix: "Disable password authentication and root login in sshd_config.",
		References: []string{
			"https://www.ssh.com/academy/ssh/sshd_config",
			"https://infosec.mozilla.org/guidelines/openssh",
		},
		CWE:        []string{"CWE-287"},
		OWASP:      []string{"A07:2021 - Identification and Authentication Failures"},
		Compliance: []string{"PCI-DSS 2.2.4", "CIS Benchmarks"},
		CodeExamples: map[string]string{
			"sshd_config": `# Secure SSH Configuration
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers admin deployer
Protocol 2
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com`,
		},
		EffortEstimate: "Low - 1-2 hours",
	}

	// Local File Inclusion
	db.recommendations["lfi"] = &Recommendation{
		VulnType:    "Local File Inclusion",
		Title:       "Local File Inclusion (LFI) Vulnerability",
		Severity:    SeverityHigh,
		Priority:    PriorityHigh,
		Description: "The application includes files based on user input without proper validation, allowing attackers to read arbitrary files from the server.",
		Impact:      "Source code disclosure, configuration file access, credential theft, and potential remote code execution via log poisoning.",
		Remediation: `1. Never use user input directly in file paths
2. Use allowlists for valid file names
3. Implement proper input validation
4. Use chroot or containerization
5. Disable dangerous PHP functions if applicable`,
		QuickFix: "Implement strict allowlist for allowed file names.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
		},
		CWE:   []string{"CWE-98", "CWE-22"},
		OWASP: []string{"A03:2021 - Injection", "A01:2021 - Broken Access Control"},
		CodeExamples: map[string]string{
			"php_vulnerable": `<?php
// VULNERABLE - Do not use
include($_GET['page'] . '.php');
?>`,
			"php_secure": `<?php
// SECURE - Use allowlist
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed)) {
    include($page . '.php');
}
?>`,
		},
		EffortEstimate: "Medium - 2-4 days",
	}

	// Open Redis
	db.recommendations["redis_unauth"] = &Recommendation{
		VulnType:    "Redis Unauthenticated Access",
		Title:       "Redis Database Without Authentication",
		Severity:    SeverityCritical,
		Priority:    PriorityCritical,
		Description: "Redis server is accessible without authentication, allowing anyone to read/write data or execute commands.",
		Impact:      "Data theft, data manipulation, server compromise through Redis exploitation techniques.",
		Remediation: `1. Enable Redis authentication (requirepass)
2. Bind Redis to localhost only (bind 127.0.0.1)
3. Use firewall rules to restrict access
4. Enable TLS for connections
5. Disable dangerous commands (CONFIG, FLUSHALL, etc.)`,
		QuickFix: "Add requirepass directive to redis.conf and restart Redis.",
		References: []string{
			"https://redis.io/docs/management/security/",
		},
		CWE:        []string{"CWE-306"},
		Compliance: []string{"PCI-DSS 2.2", "CIS Benchmarks"},
		CodeExamples: map[string]string{
			"redis_conf": `# Secure Redis Configuration
bind 127.0.0.1
protected-mode yes
requirepass YourStrongPasswordHere
rename-command CONFIG ""
rename-command FLUSHALL ""
rename-command DEBUG ""`,
		},
		EffortEstimate: "Low - 30 minutes",
	}

	// MongoDB Unauthenticated
	db.recommendations["mongodb_unauth"] = &Recommendation{
		VulnType:    "MongoDB Unauthenticated Access",
		Title:       "MongoDB Without Authentication",
		Severity:    SeverityCritical,
		Priority:    PriorityCritical,
		Description: "MongoDB is accessible without authentication, exposing all databases to unauthorized access.",
		Impact:      "Complete database compromise, data theft, ransomware attacks.",
		Remediation: `1. Enable authentication (security.authorization: enabled)
2. Create administrative users
3. Bind to localhost only
4. Use firewall rules
5. Enable TLS`,
		QuickFix: "Enable authorization in mongod.conf and create admin user.",
		References: []string{
			"https://docs.mongodb.com/manual/security/",
		},
		CWE:        []string{"CWE-306"},
		Compliance: []string{"PCI-DSS 2.2", "HIPAA"},
		CodeExamples: map[string]string{
			"mongod_conf": `# Secure MongoDB Configuration
security:
  authorization: enabled
net:
  bindIp: 127.0.0.1
  tls:
    mode: requireTLS
    certificateKeyFile: /path/to/server.pem`,
		},
		EffortEstimate: "Low - 1 hour",
	}

	// SSL/TLS Issues
	db.recommendations["ssl_weak"] = &Recommendation{
		VulnType:    "SSL/TLS Misconfiguration",
		Title:       "Weak SSL/TLS Configuration",
		Severity:    SeverityMedium,
		Priority:    PriorityMedium,
		Description: "The server supports weak SSL/TLS protocols or cipher suites that could be exploited.",
		Impact:      "Man-in-the-middle attacks, data interception, session hijacking.",
		Remediation: `1. Disable TLS 1.0 and 1.1
2. Use TLS 1.2 minimum, prefer TLS 1.3
3. Use strong cipher suites only
4. Enable HSTS
5. Implement certificate pinning for mobile apps`,
		QuickFix: "Update server configuration to disable weak protocols.",
		References: []string{
			"https://ssl-config.mozilla.org/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
		},
		CWE:        []string{"CWE-326", "CWE-327"},
		Compliance: []string{"PCI-DSS 4.1", "NIST 800-52"},
		CodeExamples: map[string]string{
			"nginx_ssl": `# Modern Nginx SSL Configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=63072000" always;`,
		},
		EffortEstimate: "Low - 1-2 hours",
	}

	// FTP Anonymous Access
	db.recommendations["ftp_anonymous"] = &Recommendation{
		VulnType:    "FTP Anonymous Access",
		Title:       "FTP Server Allows Anonymous Access",
		Severity:    SeverityMedium,
		Priority:    PriorityMedium,
		Description: "The FTP server allows anonymous login, potentially exposing files to unauthorized users.",
		Impact:      "Data leakage, unauthorized file access, potential malware upload.",
		Remediation: `1. Disable anonymous FTP access
2. Use SFTP or FTPS instead of plain FTP
3. Implement strong authentication
4. Restrict directory access
5. Monitor FTP logs`,
		QuickFix: "Disable anonymous login in FTP server configuration.",
		References: []string{
			"https://wiki.archlinux.org/title/Very_Secure_FTP_Daemon",
		},
		CWE:        []string{"CWE-284"},
		Compliance: []string{"PCI-DSS 2.2"},
		CodeExamples: map[string]string{
			"vsftpd_conf": `# Secure vsftpd Configuration
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
ssl_enable=YES`,
		},
		EffortEstimate: "Low - 30 minutes",
	}

	// Directory Listing
	db.recommendations["directory_listing"] = &Recommendation{
		VulnType:    "Directory Listing Enabled",
		Title:       "Web Server Directory Listing Enabled",
		Severity:    SeverityLow,
		Priority:    PriorityLow,
		Description: "The web server is configured to display directory contents when no index file is present.",
		Impact:      "Information disclosure, exposure of sensitive files, reconnaissance aid for attackers.",
		Remediation: `1. Disable directory listing in web server config
2. Add index files to all directories
3. Use proper access controls
4. Review exposed directories for sensitive content`,
		QuickFix: "Add 'Options -Indexes' to Apache config or 'autoindex off' to Nginx.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
		},
		CWE:   []string{"CWE-548"},
		OWASP: []string{"A01:2021 - Broken Access Control"},
		CodeExamples: map[string]string{
			"apache": `# Apache - Disable directory listing
<Directory /var/www/html>
    Options -Indexes
</Directory>`,
			"nginx": `# Nginx - Disable directory listing
location / {
    autoindex off;
}`,
		},
		EffortEstimate: "Low - 15 minutes",
	}

	// Outdated Software
	db.recommendations["outdated_software"] = &Recommendation{
		VulnType:    "Outdated Software",
		Title:       "Outdated Software with Known Vulnerabilities",
		Severity:    SeverityHigh,
		Priority:    PriorityHigh,
		Description: "The system is running outdated software versions with known security vulnerabilities.",
		Impact:      "Exploitation of known vulnerabilities, remote code execution, data breach.",
		Remediation: `1. Update to the latest stable version
2. Implement patch management process
3. Subscribe to security advisories
4. Use automated vulnerability scanning
5. Consider using containers for easier updates`,
		QuickFix:    "Apply security patches for critical vulnerabilities immediately.",
		LongTermFix: "Implement automated patch management and regular update cycles.",
		References: []string{
			"https://nvd.nist.gov/",
			"https://cve.mitre.org/",
		},
		CWE:            []string{"CWE-1104"},
		OWASP:          []string{"A06:2021 - Vulnerable and Outdated Components"},
		Compliance:     []string{"PCI-DSS 6.2", "HIPAA", "SOC 2"},
		EffortEstimate: "Varies - depends on software and changes required",
	}

	// CORS Misconfiguration
	db.recommendations["cors_misconfiguration"] = &Recommendation{
		VulnType:    "CORS Misconfiguration",
		Title:       "Cross-Origin Resource Sharing Misconfiguration",
		Severity:    SeverityMedium,
		Priority:    PriorityMedium,
		Description: "The application has overly permissive CORS settings that could allow unauthorized cross-origin requests.",
		Impact:      "Cross-site data theft, unauthorized API access, CSRF attacks.",
		Remediation: `1. Restrict Access-Control-Allow-Origin to specific domains
2. Never use wildcard (*) with credentials
3. Validate Origin header server-side
4. Limit allowed methods and headers`,
		QuickFix: "Replace wildcard CORS with specific allowed origins.",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
			"https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
		},
		CWE:   []string{"CWE-942"},
		OWASP: []string{"A05:2021 - Security Misconfiguration"},
		CodeExamples: map[string]string{
			"secure_cors": `// Secure CORS configuration
app.use(cors({
    origin: ['https://trusted-domain.com'],
    methods: ['GET', 'POST'],
    credentials: true
}));`,
		},
		EffortEstimate: "Low - 1-2 hours",
	}

	// Information Disclosure
	db.recommendations["information_disclosure"] = &Recommendation{
		VulnType:    "Information Disclosure",
		Title:       "Sensitive Information Disclosure",
		Severity:    SeverityMedium,
		Priority:    PriorityMedium,
		Description: "The application exposes sensitive information such as stack traces, version numbers, or internal paths.",
		Impact:      "Aids attackers in reconnaissance, reveals system architecture, may expose credentials.",
		Remediation: `1. Disable verbose error messages in production
2. Remove server version headers
3. Implement custom error pages
4. Review all API responses for sensitive data
5. Remove debug endpoints`,
		QuickFix: "Disable debug mode and configure custom error pages.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
		},
		CWE:            []string{"CWE-200", "CWE-209"},
		OWASP:          []string{"A05:2021 - Security Misconfiguration"},
		EffortEstimate: "Low - 2-4 hours",
	}

	// Command Injection
	db.recommendations["command_injection"] = &Recommendation{
		VulnType:    "Command Injection",
		Title:       "OS Command Injection Vulnerability",
		Severity:    SeverityCritical,
		Priority:    PriorityCritical,
		Description: "The application passes user input to system commands without proper sanitization, allowing arbitrary command execution.",
		Impact:      "Complete server compromise, data theft, lateral movement, ransomware deployment.",
		Remediation: `1. Avoid calling OS commands with user input
2. Use language-native functions instead of shell commands
3. If unavoidable, use strict allowlists
4. Use parameterized commands
5. Run with least privilege`,
		QuickFix: "Replace shell command execution with language-native APIs.",
		References: []string{
			"https://owasp.org/www-community/attacks/Command_Injection",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
		CWE:   []string{"CWE-78"},
		OWASP: []string{"A03:2021 - Injection"},
		CodeExamples: map[string]string{
			"python_vulnerable": `# VULNERABLE - Do not use
import os
os.system("ping -c 1 " + user_input)`,
			"python_secure": `# SECURE - Use subprocess with list arguments
import subprocess
import shlex
# Validate input first
if re.match(r'^[\d.]+$', user_input):
    subprocess.run(["ping", "-c", "1", user_input], capture_output=True)`,
		},
		EffortEstimate: "Medium - 2-5 days",
	}

	// Missing Security Headers
	db.recommendations["missing_headers"] = &Recommendation{
		VulnType:    "Missing Security Headers",
		Title:       "Missing HTTP Security Headers",
		Severity:    SeverityLow,
		Priority:    PriorityLow,
		Description: "The application is missing important HTTP security headers that help prevent common attacks.",
		Impact:      "Increased vulnerability to XSS, clickjacking, and other client-side attacks.",
		Remediation: `Add the following security headers:
1. Content-Security-Policy
2. X-Content-Type-Options: nosniff
3. X-Frame-Options: DENY
4. Strict-Transport-Security
5. Referrer-Policy
6. Permissions-Policy`,
		QuickFix: "Add security headers to your web server configuration.",
		References: []string{
			"https://owasp.org/www-project-secure-headers/",
			"https://securityheaders.com/",
		},
		CWE:   []string{"CWE-693"},
		OWASP: []string{"A05:2021 - Security Misconfiguration"},
		CodeExamples: map[string]string{
			"nginx_headers": `# Nginx Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
		},
		EffortEstimate: "Low - 1 hour",
	}

	// SSRF
	db.recommendations["ssrf"] = &Recommendation{
		VulnType:    "Server-Side Request Forgery",
		Title:       "Server-Side Request Forgery (SSRF) Vulnerability",
		Severity:    SeverityHigh,
		Priority:    PriorityHigh,
		Description: "The application makes requests to URLs specified by user input without proper validation, allowing attackers to access internal resources.",
		Impact:      "Access to internal services, cloud metadata exposure, port scanning, data exfiltration.",
		Remediation: `1. Use allowlists for allowed domains/IPs
2. Block requests to private IP ranges
3. Disable unnecessary URL schemes
4. Use a separate network zone for outbound requests
5. Implement proper URL validation`,
		QuickFix: "Implement URL allowlist and block private IP ranges.",
		References: []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		},
		CWE:            []string{"CWE-918"},
		OWASP:          []string{"A10:2021 - Server-Side Request Forgery"},
		EffortEstimate: "Medium - 2-4 days",
	}
}

// GenerateRemediationReport creates a formatted report for a set of findings
func (db *Database) GenerateRemediationReport(findings []string) string {
	var sb strings.Builder

	sb.WriteString("# Remediation Report\n\n")
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("This report provides remediation guidance for identified vulnerabilities.\n\n")

	// Group by priority
	critical := make([]*Recommendation, 0)
	high := make([]*Recommendation, 0)
	medium := make([]*Recommendation, 0)
	low := make([]*Recommendation, 0)

	for _, finding := range findings {
		if rec := db.Get(finding); rec != nil {
			switch rec.Priority {
			case PriorityCritical:
				critical = append(critical, rec)
			case PriorityHigh:
				high = append(high, rec)
			case PriorityMedium:
				medium = append(medium, rec)
			default:
				low = append(low, rec)
			}
		}
	}

	sb.WriteString("## Remediation Priority\n\n")
	sb.WriteString(fmt.Sprintf("- Critical: %d findings\n", len(critical)))
	sb.WriteString(fmt.Sprintf("- High: %d findings\n", len(high)))
	sb.WriteString(fmt.Sprintf("- Medium: %d findings\n", len(medium)))
	sb.WriteString(fmt.Sprintf("- Low: %d findings\n\n", len(low)))

	// Output recommendations by priority
	if len(critical) > 0 {
		sb.WriteString("## Critical Priority (Fix Immediately)\n\n")
		for _, rec := range critical {
			sb.WriteString(formatRecommendation(rec))
		}
	}

	if len(high) > 0 {
		sb.WriteString("## High Priority (Fix Within 7 Days)\n\n")
		for _, rec := range high {
			sb.WriteString(formatRecommendation(rec))
		}
	}

	if len(medium) > 0 {
		sb.WriteString("## Medium Priority (Fix Within 30 Days)\n\n")
		for _, rec := range medium {
			sb.WriteString(formatRecommendation(rec))
		}
	}

	if len(low) > 0 {
		sb.WriteString("## Low Priority (Fix Within 90 Days)\n\n")
		for _, rec := range low {
			sb.WriteString(formatRecommendation(rec))
		}
	}

	return sb.String()
}

func formatRecommendation(rec *Recommendation) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("### %s\n\n", rec.Title))
	sb.WriteString(fmt.Sprintf("**Severity:** %s | **Effort:** %s\n\n", rec.Severity, rec.EffortEstimate))
	sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", rec.Description))
	sb.WriteString(fmt.Sprintf("**Impact:** %s\n\n", rec.Impact))
	sb.WriteString(fmt.Sprintf("**Remediation:**\n%s\n\n", rec.Remediation))

	if rec.QuickFix != "" {
		sb.WriteString(fmt.Sprintf("**Quick Fix:** %s\n\n", rec.QuickFix))
	}

	if len(rec.CWE) > 0 {
		sb.WriteString(fmt.Sprintf("**CWE:** %s\n", strings.Join(rec.CWE, ", ")))
	}
	if len(rec.OWASP) > 0 {
		sb.WriteString(fmt.Sprintf("**OWASP:** %s\n", strings.Join(rec.OWASP, ", ")))
	}

	sb.WriteString("\n---\n\n")
	return sb.String()
}
