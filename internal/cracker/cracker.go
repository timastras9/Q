// Package cracker provides password cracking capabilities for pentestai
// Supports multiple hash types, brute force, dictionary attacks, and rule-based attacks
package cracker

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HashType represents different hash algorithms
type HashType int

const (
	HashUnknown HashType = iota
	HashMD5
	HashSHA1
	HashSHA256
	HashSHA512
	HashBcrypt
	HashNTLM
	HashMySQLOld
	HashMySQL5
	HashPostgres
	HashWPA2
	HashKerberosTGS
	HashKerberosASREP
)

func (h HashType) String() string {
	names := []string{
		"Unknown", "MD5", "SHA1", "SHA256", "SHA512",
		"bcrypt", "NTLM", "MySQL-Old", "MySQL5", "PostgreSQL",
		"WPA2", "Kerberos-TGS", "Kerberos-ASREP",
	}
	if int(h) < len(names) {
		return names[h]
	}
	return "Unknown"
}

// HashcatMode returns the hashcat mode for this hash type
func (h HashType) HashcatMode() string {
	modes := map[HashType]string{
		HashMD5:           "0",
		HashSHA1:          "100",
		HashSHA256:        "1400",
		HashSHA512:        "1700",
		HashBcrypt:        "3200",
		HashNTLM:          "1000",
		HashMySQLOld:      "200",
		HashMySQL5:        "300",
		HashPostgres:      "12",
		HashWPA2:          "22000",
		HashKerberosTGS:   "13100",
		HashKerberosASREP: "18200",
	}
	return modes[h]
}

// CrackedHash represents a successfully cracked hash
type CrackedHash struct {
	Hash       string
	Plaintext  string
	HashType   HashType
	Method     string // dictionary, brute, rule
	TimeToFind time.Duration
}

// CrackJob represents a cracking job
type CrackJob struct {
	ID         string
	Hashes     []string
	HashType   HashType
	Wordlist   string
	Rules      string
	BruteForce bool
	Mask       string // for brute force (e.g., ?a?a?a?a?a?a)
	MaxLength  int
	Status     string
	StartTime  time.Time
	Results    []CrackedHash
	Progress   float64
	mu         sync.Mutex
}

// Cracker provides password cracking capabilities
type Cracker struct {
	wordlistDir     string
	defaultWordlist string
	hashcatPath     string
	johnPath        string
	maxWorkers      int
}

// New creates a new Cracker instance
func New(wordlistDir string) *Cracker {
	return &Cracker{
		wordlistDir:     wordlistDir,
		defaultWordlist: "/usr/share/wordlists/rockyou.txt",
		hashcatPath:     "hashcat",
		johnPath:        "john",
		maxWorkers:      4,
	}
}

// IdentifyHash attempts to identify the hash type
func (c *Cracker) IdentifyHash(hash string) HashType {
	hash = strings.TrimSpace(hash)

	// bcrypt
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return HashBcrypt
	}

	// Kerberos TGS
	if strings.HasPrefix(hash, "$krb5tgs$") {
		return HashKerberosTGS
	}

	// Kerberos AS-REP
	if strings.HasPrefix(hash, "$krb5asrep$") {
		return HashKerberosASREP
	}

	// MySQL5
	if strings.HasPrefix(hash, "*") && len(hash) == 41 {
		return HashMySQL5
	}

	// PostgreSQL
	if strings.HasPrefix(hash, "md5") && len(hash) == 35 {
		return HashPostgres
	}

	// Length-based detection for hex hashes
	if isHex(hash) {
		switch len(hash) {
		case 32:
			return HashMD5 // Could also be NTLM
		case 40:
			return HashSHA1
		case 64:
			return HashSHA256
		case 128:
			return HashSHA512
		}
	}

	return HashUnknown
}

// CrackDictionary attempts to crack hashes using a wordlist
func (c *Cracker) CrackDictionary(ctx context.Context, hashes []string, hashType HashType, wordlist string) ([]CrackedHash, error) {
	if wordlist == "" {
		wordlist = c.defaultWordlist
	}

	var results []CrackedHash
	var mu sync.Mutex

	// Open wordlist
	file, err := os.Open(wordlist)
	if err != nil {
		// Fall back to built-in common passwords
		return c.crackWithCommonPasswords(ctx, hashes, hashType)
	}
	defer file.Close()

	// Create hash lookup map
	hashMap := make(map[string]bool)
	for _, h := range hashes {
		hashMap[strings.ToLower(h)] = true
	}

	startTime := time.Now()
	scanner := bufio.NewScanner(file)

	// Process wordlist with workers
	wordChan := make(chan string, 1000)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < c.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordChan {
				select {
				case <-ctx.Done():
					return
				default:
					computed := c.computeHash(word, hashType)
					if hashMap[strings.ToLower(computed)] {
						mu.Lock()
						results = append(results, CrackedHash{
							Hash:       computed,
							Plaintext:  word,
							HashType:   hashType,
							Method:     "dictionary",
							TimeToFind: time.Since(startTime),
						})
						delete(hashMap, strings.ToLower(computed))
						mu.Unlock()
					}
				}
			}
		}()
	}

	// Feed words to workers
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			close(wordChan)
			wg.Wait()
			return results, ctx.Err()
		default:
			wordChan <- scanner.Text()
		}

		// Check if all hashes cracked
		mu.Lock()
		remaining := len(hashMap)
		mu.Unlock()
		if remaining == 0 {
			break
		}
	}

	close(wordChan)
	wg.Wait()

	return results, nil
}

// CrackBruteForce attempts to crack hashes using brute force
func (c *Cracker) CrackBruteForce(ctx context.Context, hashes []string, hashType HashType, charset string, minLen, maxLen int) ([]CrackedHash, error) {
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	}
	if maxLen == 0 {
		maxLen = 6 // Default max length for brute force
	}

	var results []CrackedHash
	var mu sync.Mutex

	// Create hash lookup map
	hashMap := make(map[string]bool)
	for _, h := range hashes {
		hashMap[strings.ToLower(h)] = true
	}

	startTime := time.Now()
	chars := []rune(charset)

	// Generate and test all combinations
	var generate func(current []rune, length int)
	generate = func(current []rune, length int) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if len(current) == length {
			word := string(current)
			computed := c.computeHash(word, hashType)
			if hashMap[strings.ToLower(computed)] {
				mu.Lock()
				results = append(results, CrackedHash{
					Hash:       computed,
					Plaintext:  word,
					HashType:   hashType,
					Method:     "brute-force",
					TimeToFind: time.Since(startTime),
				})
				delete(hashMap, strings.ToLower(computed))
				mu.Unlock()
			}
			return
		}

		for _, c := range chars {
			mu.Lock()
			remaining := len(hashMap)
			mu.Unlock()
			if remaining == 0 {
				return
			}
			generate(append(current, c), length)
		}
	}

	// Try each length
	for length := minLen; length <= maxLen; length++ {
		mu.Lock()
		remaining := len(hashMap)
		mu.Unlock()
		if remaining == 0 {
			break
		}
		generate([]rune{}, length)
	}

	return results, nil
}

// CrackWithHashcat uses hashcat for GPU-accelerated cracking
func (c *Cracker) CrackWithHashcat(ctx context.Context, hashFile string, hashType HashType, wordlist string) ([]CrackedHash, error) {
	mode := hashType.HashcatMode()
	if mode == "" {
		return nil, fmt.Errorf("unsupported hash type for hashcat: %s", hashType)
	}

	args := []string{
		"-m", mode,
		"-a", "0", // Dictionary attack
		hashFile,
		wordlist,
		"--potfile-disable",
		"--quiet",
		"-o", hashFile + ".cracked",
	}

	cmd := exec.CommandContext(ctx, c.hashcatPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's just "no hashes loaded" or similar
		if strings.Contains(string(output), "No hashes loaded") {
			return nil, nil
		}
	}

	// Parse results
	return c.parseHashcatOutput(hashFile+".cracked", hashType)
}

// CrackWPA2Handshake attempts to crack a WPA2 handshake capture
func (c *Cracker) CrackWPA2Handshake(ctx context.Context, captureFile, wordlist string) ([]CrackedHash, error) {
	args := []string{
		"-m", "22000",
		"-a", "0",
		captureFile,
		wordlist,
		"--potfile-disable",
		"--quiet",
		"-o", captureFile + ".cracked",
	}

	cmd := exec.CommandContext(ctx, c.hashcatPath, args...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		// Try with aircrack-ng as fallback
		return c.crackWPA2WithAircrack(ctx, captureFile, wordlist)
	}

	return c.parseHashcatOutput(captureFile+".cracked", HashWPA2)
}

// crackWPA2WithAircrack uses aircrack-ng for WPA2 cracking
func (c *Cracker) crackWPA2WithAircrack(ctx context.Context, captureFile, wordlist string) ([]CrackedHash, error) {
	args := []string{
		"-w", wordlist,
		"-b", "auto",
		captureFile,
	}

	cmd := exec.CommandContext(ctx, "aircrack-ng", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("aircrack-ng failed: %w", err)
	}

	// Parse aircrack-ng output for cracked key
	var results []CrackedHash
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "KEY FOUND!") {
			// Extract the key
			re := regexp.MustCompile(`KEY FOUND! \[ (.+) \]`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				results = append(results, CrackedHash{
					Hash:      captureFile,
					Plaintext: matches[1],
					HashType:  HashWPA2,
					Method:    "aircrack-ng",
				})
			}
		}
	}

	return results, nil
}

// Common passwords for fallback when no wordlist available
var commonPasswords = []string{
	"password", "123456", "password123", "admin", "letmein", "welcome",
	"monkey", "dragon", "master", "qwerty", "login", "password1",
	"abc123", "111111", "123123", "admin123", "root", "toor",
	"pass", "test", "guest", "master123", "changeme", "123456789",
	"12345678", "1234567890", "password!", "P@ssw0rd", "Password1",
	"admin@123", "root123", "guest123", "company123", "summer2024",
}

func (c *Cracker) crackWithCommonPasswords(ctx context.Context, hashes []string, hashType HashType) ([]CrackedHash, error) {
	var results []CrackedHash

	hashMap := make(map[string]bool)
	for _, h := range hashes {
		hashMap[strings.ToLower(h)] = true
	}

	startTime := time.Now()

	for _, pwd := range commonPasswords {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		computed := c.computeHash(pwd, hashType)
		if hashMap[strings.ToLower(computed)] {
			results = append(results, CrackedHash{
				Hash:       computed,
				Plaintext:  pwd,
				HashType:   hashType,
				Method:     "common-passwords",
				TimeToFind: time.Since(startTime),
			})
			delete(hashMap, strings.ToLower(computed))
		}
	}

	return results, nil
}

func (c *Cracker) computeHash(plaintext string, hashType HashType) string {
	switch hashType {
	case HashMD5:
		sum := md5.Sum([]byte(plaintext))
		return hex.EncodeToString(sum[:])

	case HashSHA1:
		sum := sha1.Sum([]byte(plaintext))
		return hex.EncodeToString(sum[:])

	case HashSHA256:
		sum := sha256.Sum256([]byte(plaintext))
		return hex.EncodeToString(sum[:])

	case HashNTLM:
		// Simplified NTLM - would need proper implementation
		// This is a placeholder
		return ""

	case HashBcrypt:
		// For bcrypt, we verify rather than compute
		return ""

	default:
		return ""
	}
}

// VerifyBcrypt verifies a password against a bcrypt hash
func (c *Cracker) VerifyBcrypt(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (c *Cracker) parseHashcatOutput(outputFile string, hashType HashType) ([]CrackedHash, error) {
	file, err := os.Open(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []CrackedHash
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			results = append(results, CrackedHash{
				Hash:      parts[0],
				Plaintext: parts[1],
				HashType:  hashType,
				Method:    "hashcat",
			})
		}
	}

	return results, scanner.Err()
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// NetworkCredentialTest tests credentials against network services
type NetworkCredentialTest struct {
	Service  string
	Host     string
	Port     int
	Username string
	Password string
	Success  bool
	Error    string
}

// TestSSHCredentials tests SSH credentials using hydra or ncrack
func (c *Cracker) TestSSHCredentials(ctx context.Context, host string, port int, userlist, passlist string) ([]NetworkCredentialTest, error) {
	args := []string{
		"-L", userlist,
		"-P", passlist,
		fmt.Sprintf("ssh://%s:%d", host, port),
		"-t", "4",
		"-f", // Stop on first valid
	}

	cmd := exec.CommandContext(ctx, "hydra", args...)
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "valid password") {
		return nil, fmt.Errorf("hydra failed: %w", err)
	}

	return c.parseHydraOutput(string(output), "ssh", host, port)
}

// TestFTPCredentials tests FTP credentials
func (c *Cracker) TestFTPCredentials(ctx context.Context, host string, port int, userlist, passlist string) ([]NetworkCredentialTest, error) {
	args := []string{
		"-L", userlist,
		"-P", passlist,
		fmt.Sprintf("ftp://%s:%d", host, port),
		"-t", "4",
	}

	cmd := exec.CommandContext(ctx, "hydra", args...)
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(output), "valid password") {
		return nil, fmt.Errorf("hydra failed: %w", err)
	}

	return c.parseHydraOutput(string(output), "ftp", host, port)
}

func (c *Cracker) parseHydraOutput(output, service, host string, port int) ([]NetworkCredentialTest, error) {
	var results []NetworkCredentialTest

	lines := strings.Split(output, "\n")
	re := regexp.MustCompile(`\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (.+)`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 4 {
			results = append(results, NetworkCredentialTest{
				Service:  service,
				Host:     host,
				Port:     port,
				Username: matches[4],
				Password: strings.TrimSpace(matches[5]),
				Success:  true,
			})
		}
	}

	return results, nil
}
