package services

import (
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
)

func EmailAuthPolicyFromConfig(cfg *config.AuthServiceConfig) config.EmailAuthPolicy {
	defaults := config.GetDefaultSecurityConfig().EmailAuthPolicy
	if cfg == nil || cfg.SecurityConfig == nil {
		return defaults
	}
	policy := cfg.SecurityConfig.EmailAuthPolicy
	if policy.CodeTTL <= 0 {
		policy.CodeTTL = defaults.CodeTTL
	}
	if policy.LinkTTL <= 0 {
		policy.LinkTTL = defaults.LinkTTL
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = defaults.MaxAttempts
	}
	if policy.ResendInterval <= 0 {
		policy.ResendInterval = defaults.ResendInterval
	}
	return policy
}

func defaultEmailAuthPolicy() config.EmailAuthPolicy {
	policy := config.GetDefaultSecurityConfig().EmailAuthPolicy
	if policy.CodeTTL <= 0 {
		policy.CodeTTL = 10 * time.Minute
	}
	if policy.LinkTTL <= 0 {
		policy.LinkTTL = 30 * time.Minute
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = 5
	}
	if policy.ResendInterval <= 0 {
		policy.ResendInterval = time.Minute
	}
	return policy
}
