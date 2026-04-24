package config

import (
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

type AALPolicy struct {
	AALTimeout time.Duration `json:"aal_timeout"`

	AllowDowngrade bool `json:"allow_downgrade"`
}

type SecurityConfig struct {
	AALPolicy AALPolicy `json:"aal_policy"`

	PasswordUpdateConfig PasswordUpdateConfig `json:"password_update_config"`

	PasswordStrengthConfig PasswordStrengthConfig `json:"password_strength_config"`

	EmailChangeConfig IdentityChangeConfig `json:"email_change_config"`

	PhoneChangeConfig IdentityChangeConfig `json:"phone_change_config"`
}

type PasswordUpdateConfig struct {
	UpdateRequiredAAL types.AALLevel `json:"update_required_aal"`

	RevokeOtherSessions bool `json:"revoke_other_sessions"`

	RateLimit RateLimit `json:"rate_limit"`
}

type PasswordStrengthConfig struct {
	MinScore int `json:"min_score"`
}

type IdentityChangeConfig struct {
	RequiredAAL types.AALLevel `json:"required_aal"`

	RequireCurrentValueConfirmation bool `json:"require_current_value_confirmation"`

	RateLimit RateLimit `json:"rate_limit"`
}

func GetDefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		AALPolicy: AALPolicy{
			AALTimeout:     30 * time.Minute,
			AllowDowngrade: true,
		},
		PasswordUpdateConfig: PasswordUpdateConfig{
			UpdateRequiredAAL:   types.AALLevel2,
			RevokeOtherSessions: true,
			RateLimit: RateLimit{
				MaxRequests:    5,
				WindowDuration: time.Hour,
				Description:    "Password update rate limit per user",
			},
		},
		PasswordStrengthConfig: PasswordStrengthConfig{
			MinScore: 2,
		},
		EmailChangeConfig: IdentityChangeConfig{
			RequiredAAL:                     types.AALLevel2,
			RequireCurrentValueConfirmation: false,
			RateLimit: RateLimit{
				MaxRequests:    5,
				WindowDuration: time.Hour,
				Description:    "Email change rate limit per user",
			},
		},
		PhoneChangeConfig: IdentityChangeConfig{
			RequiredAAL:                     types.AALLevel2,
			RequireCurrentValueConfirmation: false,
			RateLimit: RateLimit{
				MaxRequests:    5,
				WindowDuration: time.Hour,
				Description:    "Phone change rate limit per user",
			},
		},
	}
}
