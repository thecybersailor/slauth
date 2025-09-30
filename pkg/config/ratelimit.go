package config

import "time"

// RatelimitConfig defines rate limiting configurations for various operations
type RatelimitConfig struct {
	// Email rate limiting
	EmailRateLimit RateLimit `json:"email_rate_limit"`

	// SMS rate limiting
	SMSRateLimit RateLimit `json:"sms_rate_limit"`

	// Token refresh rate limiting
	TokenRefreshRateLimit RateLimit `json:"token_refresh_rate_limit"`

	// Token verification rate limiting
	TokenVerificationRateLimit RateLimit `json:"token_verification_rate_limit"`

	// Anonymous users rate limiting
	AnonymousUsersRateLimit RateLimit `json:"anonymous_users_rate_limit"`

	// Sign up and sign in rate limiting
	SignUpSignInRateLimit RateLimit `json:"sign_up_sign_in_rate_limit"`

	// Web3 sign up and sign in rate limiting
	Web3SignUpSignInRateLimit RateLimit `json:"web3_sign_up_sign_in_rate_limit"`
}

// RateLimit defines the structure for rate limiting configuration
type RateLimit struct {
	// MaxRequests is the maximum number of requests allowed
	MaxRequests int `json:"max_requests"`

	// WindowDuration is the time window for the rate limit
	WindowDuration time.Duration `json:"window_duration"`

	// Description provides context about what this rate limit applies to
	Description string `json:"description"`
}

// GetDefaultRatelimitConfig returns the default rate limiting configuration
func GetDefaultRatelimitConfig() *RatelimitConfig {
	return &RatelimitConfig{
		EmailRateLimit: RateLimit{
			MaxRequests:    30,
			WindowDuration: time.Hour,
			Description:    "Number of emails that can be sent per hour from your project",
		},
		SMSRateLimit: RateLimit{
			MaxRequests:    150,
			WindowDuration: time.Hour,
			Description:    "Number of SMS messages that can be sent per hour from your project",
		},
		TokenRefreshRateLimit: RateLimit{
			MaxRequests:    30,
			WindowDuration: 5 * time.Minute,
			Description:    "Number of sessions that can be refreshed in a 5 minute interval per IP address",
		},
		TokenVerificationRateLimit: RateLimit{
			MaxRequests:    30,
			WindowDuration: 5 * time.Minute,
			Description:    "Number of OTP/Magic link verifications that can be made in a 5 minute interval per IP address",
		},
		AnonymousUsersRateLimit: RateLimit{
			MaxRequests:    30,
			WindowDuration: time.Hour,
			Description:    "Number of anonymous sign-ins that can be made per hour per IP address",
		},
		SignUpSignInRateLimit: RateLimit{
			MaxRequests:    30,
			WindowDuration: 5 * time.Minute,
			Description:    "Number of sign up and sign-in requests that can be made in a 5 minute interval per IP address (excludes anonymous users)",
		},
		Web3SignUpSignInRateLimit: RateLimit{
			MaxRequests:    30,
			WindowDuration: 5 * time.Minute,
			Description:    "Number of Web3 (Sign in with Solana) sign up or sign in requests that can be made per IP address in 5 minutes",
		},
	}
}
