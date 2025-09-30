package config

import (
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

type AALPolicy struct {
	AALTimeout time.Duration

	AllowDowngrade bool
}

type SecurityConfig struct {
	AALPolicy AALPolicy

	PasswordUpdateConfig PasswordUpdateConfig

	PasswordStrengthConfig PasswordStrengthConfig
}

type PasswordUpdateConfig struct {
	UpdateRequiredAAL types.AALLevel

	RevokeOtherSessions bool

	RateLimit RateLimit
}

type PasswordStrengthConfig struct {
	MinScore int
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
	}
}
