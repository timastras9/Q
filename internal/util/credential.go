package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SanitizedCredential represents a credential safe for storage/display
// The password is hashed with a salt for liability protection
type SanitizedCredential struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // SHA256(salt + password)
	Salt         string `json:"salt"`          // Random salt used for hashing
	Service      string `json:"service"`
	Target       string `json:"target"`
	Source       string `json:"source,omitempty"`
	Type         string `json:"type,omitempty"` // password, hash, key, token
}

// HashPassword creates a salted SHA256 hash of a password
// Returns the hash and salt as hex strings
func HashPassword(password, salt string) string {
	if password == "" {
		return ""
	}
	data := salt + password
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GenerateSalt creates a deterministic salt based on username and service
// This ensures the same credential always produces the same hash for deduplication
func GenerateSalt(username, service, target string) string {
	data := fmt.Sprintf("q:%s:%s:%s", username, service, target)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes as salt
}

// SanitizePassword returns a safe representation for display
// Shows first 2 chars, length indicator, and partial hash
func SanitizePassword(password string) string {
	if password == "" {
		return "[empty]"
	}

	length := len(password)

	// Show pattern like: "ad*****(8) [hash:a1b2c3d4]"
	prefix := ""
	if length >= 2 {
		prefix = password[:2]
	} else if length == 1 {
		prefix = password[:1]
	}

	// Create partial hash for verification
	hash := sha256.Sum256([]byte(password))
	partialHash := hex.EncodeToString(hash[:4])

	masked := strings.Repeat("*", min(length-len(prefix), 10))
	return fmt.Sprintf("%s%s(%d) [hash:%s]", prefix, masked, length, partialHash)
}

// MaskPassword completely masks a password showing only length
func MaskPassword(password string) string {
	if password == "" {
		return "[empty]"
	}
	return fmt.Sprintf("[%d chars]", len(password))
}

// CredentialDisplayString formats a credential for safe display
func CredentialDisplayString(username, password, service, target string) string {
	sanitized := SanitizePassword(password)
	return fmt.Sprintf("%s:%s @ %s (%s)", username, sanitized, service, target)
}

// CredentialForReport formats a credential for report output
// Shows service, username, and hashed password
func CredentialForReport(username, password, service, target string) map[string]string {
	salt := GenerateSalt(username, service, target)
	hash := HashPassword(password, salt)

	return map[string]string{
		"service":       service,
		"username":      username,
		"password_hash": hash,
		"salt":          salt,
		"target":        target,
		"display":       SanitizePassword(password),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
