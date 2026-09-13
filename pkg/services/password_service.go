package services

import (
	"unicode/utf8"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
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
	minLength        int
	maxLength        int
	maxBytes         int
}

// NewPasswordService creates a new password service with a custom encoder
// If encoder is nil, it uses the default Argon2id encoder
func NewPasswordService(config *PasswordConfig, appSecret string, strengthMinScore int) *PasswordService {
	encoder := NewArgon2idEncoder(config, appSecret)
	policy := defaultPasswordStrengthConfig()
	policy.MinScore = strengthMinScore
	return newPasswordServiceWithEncoderAndPolicy(encoder, policy)
}

func NewPasswordServiceWithPolicy(pwConfig *PasswordConfig, appSecret string, policy config.PasswordStrengthConfig) *PasswordService {
	encoder := NewArgon2idEncoder(pwConfig, appSecret)
	return newPasswordServiceWithEncoderAndPolicy(encoder, policy)
}

// NewPasswordServiceWithEncoder creates a new password service with a custom encoder
func NewPasswordServiceWithEncoder(encoder PasswordEncoder, strengthMinScore int) *PasswordService {
	policy := defaultPasswordStrengthConfig()
	policy.MinScore = strengthMinScore
	return newPasswordServiceWithEncoderAndPolicy(encoder, policy)
}

func NewPasswordServiceWithEncoderAndPolicy(encoder PasswordEncoder, policy config.PasswordStrengthConfig) *PasswordService {
	return newPasswordServiceWithEncoderAndPolicy(encoder, policy)
}

func newPasswordServiceWithEncoderAndPolicy(encoder PasswordEncoder, policy config.PasswordStrengthConfig) *PasswordService {
	policy = normalizePasswordStrengthConfig(policy)
	return &PasswordService{
		encoder:          encoder,
		strengthMinScore: policy.MinScore,
		minLength:        policy.MinLength,
		maxLength:        policy.MaxLength,
		maxBytes:         policy.MaxBytes,
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

func (p *PasswordService) ValidateNewPassword(password string) error {
	if err := validatePasswordLength(password, p.minLength, p.maxLength, p.maxBytes); err != nil {
		return err
	}
	if !p.ValidatePasswordStrength(password) {
		return consts.WEAK_PASSWORD
	}
	return nil
}

func (p *PasswordService) ValidatePasswordLoginInput(password string) error {
	if password == "" {
		return consts.VALIDATION_FAILED
	}
	if !utf8.ValidString(password) || len(password) > p.maxBytes {
		return consts.INVALID_CREDENTIALS
	}
	return nil
}

// ValidatePasswordStrength validates password strength using zxcvbn
func (p *PasswordService) ValidatePasswordStrength(password string) bool {
	// Use zxcvbn for intelligent password strength analysis
	result := zxcvbn.PasswordStrength(password, nil)

	// Use configured minimum score
	return result.Score >= p.strengthMinScore
}

func validatePasswordLength(password string, min, max, maxBytes int) error {
	if password == "" {
		return consts.VALIDATION_FAILED
	}
	if !utf8.ValidString(password) || len(password) > maxBytes {
		return consts.VALIDATION_FAILED
	}
	count := utf8.RuneCountInString(password)
	if count < min {
		return consts.WEAK_PASSWORD
	}
	if count > max {
		return consts.VALIDATION_FAILED
	}
	return nil
}

func normalizePasswordStrengthConfig(policy config.PasswordStrengthConfig) config.PasswordStrengthConfig {
	defaults := defaultPasswordStrengthConfig()
	if policy.MinScore == 0 {
		policy.MinScore = defaults.MinScore
	}
	if policy.MinLength == 0 {
		policy.MinLength = defaults.MinLength
	}
	if policy.MaxLength == 0 {
		policy.MaxLength = defaults.MaxLength
	}
	if policy.MaxBytes == 0 {
		policy.MaxBytes = defaults.MaxBytes
	}
	return policy
}

func defaultPasswordStrengthConfig() config.PasswordStrengthConfig {
	return config.PasswordStrengthConfig{
		MinScore:  2,
		MinLength: 8,
		MaxLength: 128,
		MaxBytes:  512,
	}
}
