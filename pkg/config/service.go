package config

import (
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

type AuthServiceConfig struct {

	// Site URL
	// Configure the default redirect URL used when a redirect URL is not specified or doesn't match one from the allow list. This value is also exposed as a template variable in the email templates section. Wildcards cannot be used here.
	SiteURL string `json:"site_url"`

	AuthServiceBaseUrl string `json:"auth_service_base_url"`

	// Redirect URLs
	// URLs that auth providers are permitted to redirect to post authentication. Wildcards are allowed, for example, https://*.instance.com
	RedirectURLs []string `json:"redirect_urls"`

	// If this is disabled, new users will not be able to sign up to your application
	AllowNewUsers *bool `json:"allow_new_users"`

	// Enable manual linking APIs for your project
	ManualLinking *bool `json:"manual_linking"`

	// Enable anonymous sign-ins for your project
	AnonymousSignIns *bool `json:"anonymous_sign_ins"`

	// Users will need to confirm their email address before signing in for the first time
	ConfirmEmail *bool `json:"confirm_email"`

	MFAUpdateRequiredAAL types.AALLevel `json:"mfa_update_required_aal"`

	// Maximum number of per-user MFA factors
	MaximumMfaFactors int `json:"maximum_mfa_factors"`

	// Maximum number of attempts to validate an MFA factor
	MaximumMfaFactorValidationAttempts int `json:"maximum_mfa_factor_validation_attempts"`

	// Enable Captcha protection
	// Protect authentication endpoints from bots and abuse.
	EnableCaptcha *bool `json:"enable_captcha"`

	// Maximum time allowed for an Auth request to last
	// Number of seconds to wait for an Auth request to complete before canceling it.
	// In certain high-load situations setting a larger or smaller value can be used
	// to control load-shedding. Recommended: 10 seconds.
	MaxTimeAllowedForAuthRequest time.Duration `json:"max_time_allowed_for_auth_request"`

	// Session configuration
	SessionConfig *SessionConfig `json:"session_config"`

	// Rate limiting configuration
	RatelimitConfig *RatelimitConfig `json:"ratelimit_config"`

	// Security configuration
	SecurityConfig *SecurityConfig `json:"security_config"`

	JWTSecret string `json:"-"`

	// Used as salt for hashid generation, password hashing, and Redis key prefixing
	// Should be unique per application instance for security and test isolation
	AppSecret string `json:"-"`

	// Internal field to track when config was last updated
	// Used for rate limit key generation to invalidate old rate limit records
	updatedAt time.Time
}

func NewDefaultAuthServiceConfig() *AuthServiceConfig {
	trueVal := true
	falseVal := false
	return &AuthServiceConfig{
		RedirectURLs:                       []string{},
		AllowNewUsers:                      &trueVal,
		ManualLinking:                      &falseVal,
		AnonymousSignIns:                   &falseVal,
		ConfirmEmail:                       &trueVal,
		MaximumMfaFactors:                  10,
		MaximumMfaFactorValidationAttempts: 5,
		EnableCaptcha:                      &falseVal,
		MaxTimeAllowedForAuthRequest:       10 * time.Second,
		SessionConfig:                      GetDefaultSessionConfig(),
		RatelimitConfig:                    GetDefaultRatelimitConfig(),
		SecurityConfig:                     GetDefaultSecurityConfig(),
		JWTSecret:                          "",
		AppSecret:                          "",
	}
}

func NewAuthServiceConfig() *AuthServiceConfig {
	return NewDefaultAuthServiceConfig()
}

func (c *AuthServiceConfig) SetUpdatedAt(t time.Time) {
	c.updatedAt = t
}

func (c *AuthServiceConfig) UpdatedAt() time.Time {
	return c.updatedAt
}
