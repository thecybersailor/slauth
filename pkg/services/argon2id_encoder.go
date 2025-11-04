package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/thecybersailor/slauth/pkg/consts"
	"golang.org/x/crypto/argon2"
)

// Argon2idEncoder implements PasswordEncoder using Argon2id with dual salt mechanism
type Argon2idEncoder struct {
	config    *PasswordConfig
	appSecret string
}

// NewArgon2idEncoder creates a new Argon2id password encoder
func NewArgon2idEncoder(config *PasswordConfig, appSecret string) *Argon2idEncoder {
	if config == nil {
		config = DefaultPasswordConfig()
	}
	return &Argon2idEncoder{
		config:    config,
		appSecret: appSecret,
	}
}

// HashPassword hashes a password using Argon2id with dual salt mechanism
func (e *Argon2idEncoder) HashPassword(password string) (string, error) {
	// Generate random row salt
	rowSalt := make([]byte, e.config.SaltLen)
	if _, err := rand.Read(rowSalt); err != nil {
		return "", err
	}

	// Combine password with main salt (AppSecret) first
	passwordWithMainSalt := password + e.appSecret

	// Create combined salt: main salt + row salt
	combinedSalt := append([]byte(e.appSecret), rowSalt...)

	// Hash password with combined salt
	hash := argon2.IDKey([]byte(passwordWithMainSalt), combinedSalt, e.config.Time, e.config.Memory, e.config.Threads, e.config.KeyLen)

	// Encode to base64 (only store row salt, main salt is from config)
	b64RowSalt := base64.RawStdEncoding.EncodeToString(rowSalt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$rowSalt$hash
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, e.config.Memory, e.config.Time, e.config.Threads, b64RowSalt, b64Hash)

	return encoded, nil
}

// VerifyPassword verifies a password against its hash
func (e *Argon2idEncoder) VerifyPassword(password, encodedHash string) (bool, error) {
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
	passwordWithMainSalt := password + e.appSecret
	combinedSalt := append([]byte(e.appSecret), rowSalt...)

	// Hash the provided password with the same parameters
	keyLen := uint32(len(hash))
	comparisonHash := argon2.IDKey([]byte(passwordWithMainSalt), combinedSalt, time, memory, threads, keyLen)

	// Compare hashes using constant-time comparison
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1, nil
}

