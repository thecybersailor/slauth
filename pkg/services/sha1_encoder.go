package services

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// SHA1SaltEncoder implements PasswordEncoder using SHA1 with salt
// This is provided for testing purposes only and should not be used in production
type SHA1SaltEncoder struct{}

// HashPassword hashes a password using SHA1 with a random salt
// Format: hex(salt)|hex(hash)
func (e *SHA1SaltEncoder) HashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash password with salt
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(password))
	sha1Hash.Write(salt)
	hash := sha1Hash.Sum(nil)

	// Return format: hex(salt)|hex(hash)
	return hex.EncodeToString(salt) + "|" + hex.EncodeToString(hash), nil
}

// VerifyPassword verifies a password against its SHA1 hash
func (e *SHA1SaltEncoder) VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "|")
	if len(parts) != 2 {
		return false, nil
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	// Compute hash with the same salt
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(password))
	sha1Hash.Write(salt)
	computedHash := sha1Hash.Sum(nil)

	// Compare hashes
	return bytes.Equal(computedHash, expectedHash), nil
}
