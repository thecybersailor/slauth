package services

import (
	"github.com/trustelem/zxcvbn"
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
	encoder          PasswordEncoder
	strengthMinScore int
}

// NewPasswordService creates a new password service with a custom encoder
// If encoder is nil, it uses the default Argon2id encoder
func NewPasswordService(config *PasswordConfig, appSecret string, strengthMinScore int) *PasswordService {
	encoder := NewArgon2idEncoder(config, appSecret)
	return &PasswordService{
		encoder:          encoder,
		strengthMinScore: strengthMinScore,
	}
}

// NewPasswordServiceWithEncoder creates a new password service with a custom encoder
func NewPasswordServiceWithEncoder(encoder PasswordEncoder, strengthMinScore int) *PasswordService {
	return &PasswordService{
		encoder:          encoder,
		strengthMinScore: strengthMinScore,
	}
}

// HashPassword hashes a password using the configured encoder
func (p *PasswordService) HashPassword(password string) (string, error) {
	return p.encoder.HashPassword(password)
}

// VerifyPassword verifies a password against its hash using the configured encoder
func (p *PasswordService) VerifyPassword(password, encodedHash string) (bool, error) {
	return p.encoder.VerifyPassword(password, encodedHash)
}

// ValidatePasswordStrength validates password strength using zxcvbn
func (p *PasswordService) ValidatePasswordStrength(password string) bool {
	// Use zxcvbn for intelligent password strength analysis
	result := zxcvbn.PasswordStrength(password, nil)

	// Use configured minimum score
	return result.Score >= p.strengthMinScore
}
