package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

// OTPService handles OTP operations
type OTPService struct {
	issuer string
}

// NewOTPService creates a new OTP service
func NewOTPService(issuer string) *OTPService {
	return &OTPService{issuer: issuer}
}

// GenerateCode generates an OTP code for the given context
func (o *OTPService) GenerateCode(ctx OTPContext) (string, error) {
	return o.GenerateRandomOTP(6) // Default to 6-digit code
}

// GenerateRandomOTP generates a random numeric OTP
func (o *OTPService) GenerateRandomOTP(length int) (string, error) {
	if length < 4 || length > 10 {
		length = 6 // Default to 6 digits
	}

	max := int(math.Pow10(length))
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	num := binary.BigEndian.Uint32(bytes) % uint32(max)
	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, num), nil
}

// GenerateSecretKey generates a random secret key for TOTP
func (o *OTPService) GenerateSecretKey() (string, error) {
	bytes := make([]byte, 20) // 160 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(bytes), nil
}

// GenerateTOTP generates a TOTP code
func (o *OTPService) GenerateTOTP(secret string, timestamp time.Time) (string, error) {
	return o.generateTOTPWithPeriod(secret, timestamp, 30)
}

// generateTOTPWithPeriod generates TOTP with custom period
func (o *OTPService) generateTOTPWithPeriod(secret string, timestamp time.Time, period int64) (string, error) {
	// Decode base32 secret
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	// Calculate time counter
	counter := timestamp.Unix() / period

	// Generate HOTP
	return o.generateHOTP(key, counter)
}

// generateHOTP generates HOTP code
func (o *OTPService) generateHOTP(key []byte, counter int64) (string, error) {
	// Convert counter to byte array
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))

	// Generate HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// Generate 6-digit code
	otp := code % 1000000
	return fmt.Sprintf("%06d", otp), nil
}

// VerifyTOTP verifies a TOTP code
func (o *OTPService) VerifyTOTP(secret, code string, timestamp time.Time) bool {
	return o.verifyTOTPWithSkew(secret, code, timestamp, 1)
}

// verifyTOTPWithSkew verifies TOTP with time skew tolerance
func (o *OTPService) verifyTOTPWithSkew(secret, code string, timestamp time.Time, skew int) bool {
	period := int64(30)

	for i := -skew; i <= skew; i++ {
		testTime := timestamp.Add(time.Duration(i) * time.Duration(period) * time.Second)
		if expectedCode, err := o.generateTOTPWithPeriod(secret, testTime, period); err == nil {
			if expectedCode == code {
				return true
			}
		}
	}
	return false
}

// GenerateTOTPURL generates a TOTP URL for QR code
func (o *OTPService) GenerateTOTPURL(secret, accountName, issuer string) string {
	if issuer == "" {
		issuer = o.issuer
	}

	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("period", "30")

	label := url.QueryEscape(fmt.Sprintf("%s:%s", issuer, accountName))
	return fmt.Sprintf("otpauth://totp/%s?%s", label, params.Encode())
}

// GenerateBackupCodes generates backup codes for account recovery
func (o *OTPService) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Generate 8-character alphanumeric code
		bytes := make([]byte, 6)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}

		// Convert to alphanumeric
		const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		code := make([]byte, 8)
		for j := 0; j < 8; j++ {
			code[j] = charset[bytes[j%6]%byte(len(charset))]
		}

		// Format as XXXX-XXXX
		codes[i] = fmt.Sprintf("%s-%s", string(code[:4]), string(code[4:]))
	}

	return codes, nil
}

// HashOTP creates a hash of OTP for storage
func (o *OTPService) HashOTP(otp string) string {
	h := sha256.New()
	h.Write([]byte(otp))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GenerateEmailOTP generates OTP for email verification
func (o *OTPService) GenerateEmailOTP() (string, error) {
	return o.GenerateRandomOTP(6)
}

// GenerateSMSOTP generates OTP for SMS verification
func (o *OTPService) GenerateSMSOTP() (string, error) {
	return o.GenerateRandomOTP(6)
}

// ValidateOTPFormat validates OTP format
func (o *OTPService) ValidateOTPFormat(otp string) bool {
	// Check if it's numeric and has correct length
	if len(otp) < 4 || len(otp) > 10 {
		return false
	}

	for _, char := range otp {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// StoreOTP stores an OTP code for verification
func (o *OTPService) StoreOTP(ctx context.Context, email, phone, code string, tokenType types.OneTimeTokenType, domainCode string, db *gorm.DB) error {
	// Hash the OTP code for security
	codeHash := o.HashOTP(code)

	otTokenService := NewOneTimeTokenService(db)

	// Delete any existing OTP tokens for this email/phone and type (industry practice)
	if email != "" {
		err := otTokenService.DeleteByEmailAndType(ctx, email, tokenType, domainCode)
		if err != nil && err != gorm.ErrRecordNotFound {
			return consts.UNEXPECTED_FAILURE
		}
	}
	if phone != "" {
		err := otTokenService.DeleteByPhoneAndType(ctx, phone, tokenType, domainCode)
		if err != nil && err != gorm.ErrRecordNotFound {
			return consts.UNEXPECTED_FAILURE
		}
	}

	// Create new OneTimeToken record
	expiresAt := time.Now().Add(10 * time.Minute) // 10 minutes expiry
	token := &models.OneTimeToken{
		TokenHash:  codeHash,
		TokenType:  tokenType,
		DomainCode: domainCode,
		ExpiresAt:  &expiresAt,
		RelatesTo:  "otp_verification", // Default relates_to for OTP scenarios
	}

	// Set email or phone based on what's provided
	if email != "" {
		token.Email = &email
	}
	if phone != "" {
		token.Phone = &phone
	}

	// Store in database
	return otTokenService.Create(ctx, token)
}

// VerifyOTP verifies an OTP code
func (o *OTPService) VerifyOTP(ctx context.Context, email, phone, code string, tokenType types.OneTimeTokenType, domainCode string, db *gorm.DB) (bool, error) {
	// Validate OTP format first
	if !o.ValidateOTPFormat(code) {
		return false, consts.VALIDATION_FAILED
	}

	// Hash the provided code
	codeHash := o.HashOTP(code)

	// Look up the stored OTP
	otTokenService := NewOneTimeTokenService(db)
	var token *models.OneTimeToken
	var err error

	if email != "" {
		token, err = otTokenService.GetByEmailAndType(ctx, email, tokenType, domainCode)
	} else if phone != "" {
		token, err = otTokenService.GetByPhoneAndType(ctx, phone, tokenType, domainCode)
	} else {
		return false, consts.VALIDATION_FAILED
	}

	if err != nil {
		return false, err
	}

	// Check if token matches
	if token.TokenHash != codeHash {
		return false, consts.INVALID_CREDENTIALS
	}

	// Check if expired
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return false, consts.OTP_EXPIRED
	}

	// Delete the used token
	err = otTokenService.DeleteByID(ctx, token.ID, domainCode)
	if err != nil {
		// Log error but don't fail verification
		fmt.Printf("Warning: Failed to delete used OTP token: %v\n", err)
	}

	return true, nil
}

// IsOTPExpired checks if OTP is expired
func (o *OTPService) IsOTPExpired(createdAt time.Time, ttl time.Duration) bool {
	return time.Now().After(createdAt.Add(ttl))
}
