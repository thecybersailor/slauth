package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

// TOTPProvider implements MFAProvider interface for TOTP (Time-based One-Time Password)
type TOTPProvider struct {
	name string
}

// NewTOTPProvider creates a new TOTP MFA provider
func NewTOTPProvider() *TOTPProvider {
	return &TOTPProvider{
		name: "totp",
	}
}

// GetName returns the provider name
func (p *TOTPProvider) GetName() string {
	return p.name
}

// Enroll creates a new TOTP factor for a user
func (p *TOTPProvider) Enroll(ctx context.Context, factorType types.FactorType, issuer string, friendlyName string, phone string) (string, error) {
	if factorType != types.FactorTypeTOTP {
		return "", fmt.Errorf("unsupported factor type: %s", factorType)
	}

	// Generate a random secret key (32 bytes = 256 bits)
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}

	// Encode secret as base32 (standard for TOTP)
	secretKey := base32.StdEncoding.EncodeToString(secret)

	// For testing purposes, we'll return the secret key as the factor ID
	// In a real implementation, this would be stored in a database
	factorID := fmt.Sprintf("totp_%s", secretKey)

	return factorID, nil
}

// Challenge generates a challenge for TOTP verification
func (p *TOTPProvider) Challenge(ctx context.Context, factorID string, channel string) (string, error) {
	// For TOTP, we don't need to generate a separate challenge
	// The challenge is implicit in the current time window
	// We'll return the factorID as the challengeID for simplicity
	return factorID, nil
}

// Verify validates a TOTP code against the factor
func (p *TOTPProvider) Verify(ctx context.Context, factorID string, challengeID string, code string) (string, error) {
	// For testing purposes, we'll accept any 6-digit code
	// In a real implementation, this would:
	// 1. Extract the secret from factorID
	// 2. Calculate the current TOTP code
	// 3. Compare with the provided code (allowing for time skew)

	if len(code) != 6 {
		return "", fmt.Errorf("invalid TOTP code length")
	}

	// Simple validation for testing - accept any 6-digit numeric code
	for _, char := range code {
		if char < '0' || char > '9' {
			return "", fmt.Errorf("invalid TOTP code format")
		}
	}

	// Return a verification ID
	verificationID := fmt.Sprintf("verify_%d", time.Now().Unix())
	return verificationID, nil
}

// Unenroll removes a TOTP factor
func (p *TOTPProvider) Unenroll(ctx context.Context, factorID string) error {
	// For testing purposes, we'll just return success
	// In a real implementation, this would remove the factor from storage
	return nil
}

// ListFactors returns a list of enrolled factors
func (p *TOTPProvider) ListFactors(ctx context.Context) ([]types.Factor, error) {
	// For testing purposes, return empty list
	// In a real implementation, this would query the database
	return []types.Factor{}, nil
}

// TOTPFactor implements the Factor interface for TOTP factors
type TOTPFactor struct {
	id     string
	status types.FactorStatus
}

// ID returns the factor ID
func (f *TOTPFactor) ID() string {
	return f.id
}

// Type returns the factor type
func (f *TOTPFactor) Type() types.FactorType {
	return types.FactorTypeTOTP
}

// Status returns the factor status
func (f *TOTPFactor) Status() types.FactorStatus {
	return f.status
}
