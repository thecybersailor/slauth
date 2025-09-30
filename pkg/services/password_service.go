package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/trustelem/zxcvbn"
	"golang.org/x/crypto/argon2"
)

// PasswordConfig holds password hashing configuration
type PasswordConfig struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultPasswordConfig returns default password hashing configuration
func DefaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		Time:    1,
		Memory:  64 * 1024, // 64 MB
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// PasswordService handles password operations
type PasswordService struct {
	config           *PasswordConfig
	appSecret        string
	strengthMinScore int
}

// NewPasswordService creates a new password service
func NewPasswordService(config *PasswordConfig, appSecret string, strengthMinScore int) *PasswordService {
	if config == nil {
		config = DefaultPasswordConfig()
	}
	return &PasswordService{
		config:           config,
		appSecret:        appSecret,
		strengthMinScore: strengthMinScore,
	}
}

// HashPassword hashes a password using Argon2id with dual salt mechanism
func (p *PasswordService) HashPassword(password string) (string, error) {
	// Generate random row salt
	rowSalt := make([]byte, p.config.SaltLen)
	if _, err := rand.Read(rowSalt); err != nil {
		return "", err
	}

	// Combine password with main salt (AppSecret) first
	passwordWithMainSalt := password + p.appSecret

	// Create combined salt: main salt + row salt
	combinedSalt := append([]byte(p.appSecret), rowSalt...)

	// Hash password with combined salt
	hash := argon2.IDKey([]byte(passwordWithMainSalt), combinedSalt, p.config.Time, p.config.Memory, p.config.Threads, p.config.KeyLen)

	// Encode to base64 (only store row salt, main salt is from config)
	b64RowSalt := base64.RawStdEncoding.EncodeToString(rowSalt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$rowSalt$hash
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.config.Memory, p.config.Time, p.config.Threads, b64RowSalt, b64Hash)

	return encoded, nil
}

// VerifyPassword verifies a password against its hash
func (p *PasswordService) VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, consts.VALIDATION_FAILED
	}

	if parts[1] != "argon2id" {
		return false, consts.VALIDATION_FAILED
	}

	// Parse parameters
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, err
	}

	// Decode row salt and hash
	rowSalt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	// Recreate the same dual salt mechanism used during hashing
	passwordWithMainSalt := password + p.appSecret
	combinedSalt := append([]byte(p.appSecret), rowSalt...)

	// Hash the provided password with the same parameters
	keyLen := uint32(len(hash))
	comparisonHash := argon2.IDKey([]byte(passwordWithMainSalt), combinedSalt, time, memory, threads, keyLen)

	// Compare hashes using constant-time comparison
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1, nil
}

// ValidatePasswordStrength validates password strength using zxcvbn
func (p *PasswordService) ValidatePasswordStrength(password string) bool {
	// Use zxcvbn for intelligent password strength analysis
	result := zxcvbn.PasswordStrength(password, nil)

	// Use configured minimum score
	return result.Score >= p.strengthMinScore
}
