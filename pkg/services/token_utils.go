package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}
	
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	return hex.EncodeToString(bytes), nil
}

// HashToken creates a SHA256 hash of the token for secure storage
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// GenerateConfirmationToken generates a secure confirmation token and its hash
// Returns: (token, tokenHash, error)
func GenerateConfirmationToken() (string, string, error) {
	// Generate a 32-byte (256-bit) random token
	token, err := GenerateSecureToken(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate confirmation token: %w", err)
	}
	
	// Create hash for storage
	tokenHash := HashToken(token)
	
	return token, tokenHash, nil
}

// VerifyToken verifies if a plain token matches the stored hash
func VerifyToken(plainToken, storedHash string) bool {
	computedHash := HashToken(plainToken)
	return computedHash == storedHash
}
