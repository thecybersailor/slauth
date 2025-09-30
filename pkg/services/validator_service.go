package services

import (
	"net/mail"
	"regexp"
	"strings"

	"github.com/thecybersailor/slauth/pkg/consts"
)

// ValidatorService handles input validation
type ValidatorService struct{}

// NewValidatorService creates a new validator service
func NewValidatorService() *ValidatorService {
	return &ValidatorService{}
}

// ValidateEmail validates email format
func (v *ValidatorService) ValidateEmail(email string) error {
	if email == "" {
		return consts.VALIDATION_FAILED
	}

	// Basic format validation
	if _, err := mail.ParseAddress(email); err != nil {
		return consts.EMAIL_ADDRESS_INVALID
	}

	// Additional checks
	email = strings.ToLower(strings.TrimSpace(email))

	// Check length
	if len(email) > 254 {
		return consts.EMAIL_ADDRESS_INVALID
	}

	// Check for common invalid patterns
	if strings.Contains(email, "..") {
		return consts.EMAIL_ADDRESS_INVALID
	}

	if strings.HasPrefix(email, ".") || strings.HasSuffix(email, ".") {
		return consts.EMAIL_ADDRESS_INVALID
	}

	return nil
}

// ValidatePhone validates phone number format
func (v *ValidatorService) ValidatePhone(phone string) error {
	if phone == "" {
		return consts.VALIDATION_FAILED
	}

	// Remove common formatting characters
	cleaned := strings.ReplaceAll(phone, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	cleaned = strings.ReplaceAll(cleaned, ".", "")

	// Must start with + for international format
	if !strings.HasPrefix(cleaned, "+") {
		return consts.VALIDATION_FAILED
	}

	// Remove the + for digit validation
	digits := cleaned[1:]

	// Check if all remaining characters are digits
	matched, err := regexp.MatchString(`^\d+$`, digits)
	if err != nil {
		return consts.VALIDATION_FAILED
	}
	if !matched {
		return consts.VALIDATION_FAILED
	}

	// Check length (international phone numbers are typically 7-15 digits)
	if len(digits) < 7 || len(digits) > 15 {
		return consts.VALIDATION_FAILED
	}

	return nil
}

// ValidatePassword validates password requirements
func (v *ValidatorService) ValidatePassword(password string) error {
	if password == "" {
		return consts.VALIDATION_FAILED
	}

	if len(password) < 8 {
		return consts.WEAK_PASSWORD
	}

	if len(password) > 128 {
		return consts.VALIDATION_FAILED
	}

	return nil
}

// ValidateUserMetadata validates user metadata
func (v *ValidatorService) ValidateUserMetadata(metadata map[string]any) error {
	if metadata == nil {
		return nil
	}

	// Check for reserved keys
	reservedKeys := []string{
		"id", "email", "phone", "created_at", "updated_at",
		"email_confirmed_at", "phone_confirmed_at", "last_sign_in_at",
		"role", "aal", "amr", "session_id",
	}

	// Compile regex once before loop
	keyFormatRegex := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	for key := range metadata {
		for _, reserved := range reservedKeys {
			if strings.ToLower(key) == reserved {
				return consts.VALIDATION_FAILED
			}
		}

		// Validate key format
		if !keyFormatRegex.MatchString(key) {
			return consts.VALIDATION_FAILED
		}

		// Check key length
		if len(key) > 64 {
			return consts.VALIDATION_FAILED
		}
	}

	return nil
}

// ValidateRedirectURL validates redirect URL
func (v *ValidatorService) ValidateRedirectURL(redirectURL string, allowedURLs []string) error {
	if redirectURL == "" {
		return nil // Optional parameter
	}

	// Check if URL is in allowed list
	for _, allowed := range allowedURLs {
		if v.matchURL(redirectURL, allowed) {
			return nil
		}
	}

	return consts.VALIDATION_FAILED
}

// matchURL checks if URL matches pattern (supports wildcards)
func (v *ValidatorService) matchURL(url, pattern string) bool {
	// Simple wildcard matching
	if strings.Contains(pattern, "*") {
		// Convert wildcard pattern to regex
		regexPattern := strings.ReplaceAll(pattern, "*", ".*")
		regexPattern = "^" + regexPattern + "$"

		matched, err := regexp.MatchString(regexPattern, url)
		if err == nil && matched {
			return true
		}
	}

	// Exact match
	return url == pattern
}

// ValidateDomainCode validates domain code format
func (v *ValidatorService) ValidateDomainCode(domainCode string) error {
	if domainCode == "" {
		return consts.VALIDATION_FAILED
	}

	// Check format: alphanumeric, underscore, hyphen
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, domainCode)
	if err != nil {
		return consts.VALIDATION_FAILED
	}
	if !matched {
		return consts.VALIDATION_FAILED
	}

	// Check length
	if len(domainCode) < 2 || len(domainCode) > 64 {
		return consts.VALIDATION_FAILED
	}

	return nil
}

// ValidateProviderName validates OAuth provider name
func (v *ValidatorService) ValidateProviderName(provider string) error {
	if provider == "" {
		return consts.VALIDATION_FAILED
	}

	// List of supported providers
	supportedProviders := []string{
		"google", "facebook", "github", "gitlab", "bitbucket",
		"azure", "apple", "discord", "figma", "keycloak",
		"linkedin", "notion", "slack", "spotify", "twitch",
		"twitter", "workos", "zoom",
	}

	provider = strings.ToLower(provider)
	for _, supported := range supportedProviders {
		if provider == supported {
			return nil
		}
	}

	return consts.OAUTH_PROVIDER_NOT_SUPPORTED
}

// ValidateFactorType validates MFA factor type
func (v *ValidatorService) ValidateFactorType(factorType string) error {
	if factorType == "" {
		return consts.VALIDATION_FAILED
	}

	supportedTypes := []string{"totp", "phone", "webauthn"}
	factorType = strings.ToLower(factorType)

	for _, supported := range supportedTypes {
		if factorType == supported {
			return nil
		}
	}

	return consts.VALIDATION_FAILED
}

// ValidateOTPType validates OTP type
func (v *ValidatorService) ValidateOTPType(otpType string) error {
	if otpType == "" {
		return consts.VALIDATION_FAILED
	}

	supportedTypes := []string{
		"signup", "invite", "magiclink", "recovery",
		"email_change", "sms", "phone_change",
	}

	otpType = strings.ToLower(otpType)
	for _, supported := range supportedTypes {
		if otpType == supported {
			return nil
		}
	}

	return consts.VALIDATION_FAILED
}

// SanitizeEmail sanitizes email input
func (v *ValidatorService) SanitizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// SanitizePhone sanitizes phone input
func (v *ValidatorService) SanitizePhone(phone string) string {
	// Remove common formatting
	cleaned := strings.ReplaceAll(phone, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	cleaned = strings.ReplaceAll(cleaned, ".", "")

	return strings.TrimSpace(cleaned)
}
