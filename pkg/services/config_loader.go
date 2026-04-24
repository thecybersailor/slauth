package services

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type ConfigLoader struct {
	db              *gorm.DB
	secretsProvider types.InstanceSecretsProvider
	instanceId      string

	cachedConfig *config.AuthServiceConfig
	cacheMutex   sync.RWMutex
	cachedAt     time.Time
	cacheTTL     time.Duration
}

func NewConfigLoader(db *gorm.DB, secretsProvider types.InstanceSecretsProvider, instanceId string) *ConfigLoader {
	return &ConfigLoader{
		db:              db,
		secretsProvider: secretsProvider,
		instanceId:      instanceId,
		cacheTTL:        30 * time.Second,
	}
}

func (l *ConfigLoader) GetConfig() *config.AuthServiceConfig {
	l.cacheMutex.RLock()
	if l.cachedConfig != nil && time.Since(l.cachedAt) < l.cacheTTL {
		defer l.cacheMutex.RUnlock()
		return l.cachedConfig
	}
	l.cacheMutex.RUnlock()

	l.cacheMutex.Lock()
	defer l.cacheMutex.Unlock()

	if l.cachedConfig != nil && time.Since(l.cachedAt) < l.cacheTTL {
		return l.cachedConfig
	}

	cfg := l.loadFromDB()
	l.cachedConfig = cfg
	l.cachedAt = time.Now()

	return cfg
}

func (l *ConfigLoader) loadFromDB() *config.AuthServiceConfig {
	var instance models.AuthInstance

	err := l.db.Where("instance_id = ?", l.instanceId).First(&instance).Error
	if err == gorm.ErrRecordNotFound {
		return l.createDefaultInstance()
	}
	if err != nil {
		return config.NewDefaultAuthServiceConfig()
	}

	cfg := NormalizeAuthServiceConfigFromRaw(instance.Config)

	// Set UpdatedAt from database to config
	cfg.SetUpdatedAt(instance.UpdatedAt)

	// Get AppSecret from secrets provider
	if l.secretsProvider != nil {
		secrets, err := l.secretsProvider.GetSecrets(l.instanceId)
		if err == nil {
			cfg.AppSecret = secrets.AppSecret
		}
	}

	return cfg
}

func (l *ConfigLoader) createDefaultInstance() *config.AuthServiceConfig {
	cfg := config.NewDefaultAuthServiceConfig()

	instance := models.AuthInstance{
		InstanceId: l.instanceId,
		ConfigData: cfg, // BeforeSave hook will marshal this
	}

	result := l.db.Create(&instance)
	if result.Error != nil {
		// Get AppSecret from secrets provider
		if l.secretsProvider != nil {
			secrets, err := l.secretsProvider.GetSecrets(l.instanceId)
			if err == nil {
				cfg.AppSecret = secrets.AppSecret
			}
		}
		return cfg
	}

	// Set UpdatedAt from created instance
	cfg.SetUpdatedAt(instance.UpdatedAt)

	// Get AppSecret from secrets provider
	if l.secretsProvider != nil {
		secrets, err := l.secretsProvider.GetSecrets(l.instanceId)
		if err == nil {
			cfg.AppSecret = secrets.AppSecret
		}
	}

	return cfg
}

func (l *ConfigLoader) InvalidateCache() {
	l.cacheMutex.Lock()
	defer l.cacheMutex.Unlock()
	l.cachedAt = time.Time{}
}

func (l *ConfigLoader) SaveConfig(cfg *config.AuthServiceConfig) error {
	// Get current config to merge with new config
	currentConfig := l.GetConfig()

	// Merge new config with current config (partial update)
	mergedConfig := MergeAuthServiceConfig(currentConfig, cfg)

	var instance models.AuthInstance
	err := l.db.Where("instance_id = ?", l.instanceId).First(&instance).Error

	if err == gorm.ErrRecordNotFound {
		instance = models.AuthInstance{
			InstanceId: l.instanceId,
			ConfigData: mergedConfig, // BeforeSave hook will marshal this
		}
		err = l.db.Create(&instance).Error
	} else {
		instance.ConfigData = mergedConfig // BeforeSave hook will marshal this
		err = l.db.Save(&instance).Error
	}

	if err == nil {
		l.InvalidateCache()
	}

	return err
}

func (l *ConfigLoader) SaveConfigPatch(patch *config.AuthServiceConfigPatch) error {
	currentConfig := l.GetConfig()
	mergedConfig := ApplyAuthServiceConfigPatch(currentConfig, patch)

	var instance models.AuthInstance
	err := l.db.Where("instance_id = ?", l.instanceId).First(&instance).Error

	if err == gorm.ErrRecordNotFound {
		instance = models.AuthInstance{
			InstanceId: l.instanceId,
			ConfigData: mergedConfig,
		}
		err = l.db.Create(&instance).Error
	} else {
		instance.ConfigData = mergedConfig
		err = l.db.Save(&instance).Error
	}

	if err == nil {
		l.InvalidateCache()
	}

	return err
}

func NormalizeAuthServiceConfigFromRaw(raw []byte) *config.AuthServiceConfig {
	cfg := config.NewDefaultAuthServiceConfig()
	if len(raw) == 0 {
		return cfg
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return config.NewDefaultAuthServiceConfig()
	}
	return cfg
}

func NormalizeAuthServiceConfig(cfg *config.AuthServiceConfig) *config.AuthServiceConfig {
	if cfg == nil {
		return config.NewDefaultAuthServiceConfig()
	}
	return MergeAuthServiceConfig(config.NewDefaultAuthServiceConfig(), cfg)
}

func MergeAuthServiceConfig(current, next *config.AuthServiceConfig) *config.AuthServiceConfig {
	if current == nil {
		current = config.NewDefaultAuthServiceConfig()
	}
	if next == nil {
		return NormalizeAuthServiceConfig(current)
	}

	merged := *current

	if next.SiteURL != "" {
		merged.SiteURL = next.SiteURL
	}
	if next.AuthServiceBaseUrl != "" {
		merged.AuthServiceBaseUrl = next.AuthServiceBaseUrl
	}
	if next.RedirectURLs != nil {
		merged.RedirectURLs = append([]string(nil), next.RedirectURLs...)
	}
	if next.AllowNewUsers != nil {
		val := *next.AllowNewUsers
		merged.AllowNewUsers = &val
	}
	if next.ManualLinking != nil {
		val := *next.ManualLinking
		merged.ManualLinking = &val
	}
	if next.AnonymousSignIns != nil {
		val := *next.AnonymousSignIns
		merged.AnonymousSignIns = &val
	}
	if next.ConfirmEmail != nil {
		val := *next.ConfirmEmail
		merged.ConfirmEmail = &val
	}
	if next.EnableCaptcha != nil {
		val := *next.EnableCaptcha
		merged.EnableCaptcha = &val
	}
	if next.MFAUpdateRequiredAAL != "" {
		merged.MFAUpdateRequiredAAL = next.MFAUpdateRequiredAAL
	}
	if next.MaximumMfaFactors > 0 {
		merged.MaximumMfaFactors = next.MaximumMfaFactors
	}
	if next.MaximumMfaFactorValidationAttempts > 0 {
		merged.MaximumMfaFactorValidationAttempts = next.MaximumMfaFactorValidationAttempts
	}
	if next.MaxTimeAllowedForAuthRequest > 0 {
		merged.MaxTimeAllowedForAuthRequest = next.MaxTimeAllowedForAuthRequest
	}

	merged.SessionConfig = mergeSessionConfig(merged.SessionConfig, next.SessionConfig)
	merged.RatelimitConfig = mergeRatelimitConfig(merged.RatelimitConfig, next.RatelimitConfig)
	merged.SecurityConfig = mergeSecurityConfig(merged.SecurityConfig, next.SecurityConfig)

	merged.JWTSecret = current.JWTSecret
	merged.AppSecret = current.AppSecret
	merged.SetUpdatedAt(current.UpdatedAt())

	return &merged
}

func ApplyAuthServiceConfigPatch(current *config.AuthServiceConfig, patch *config.AuthServiceConfigPatch) *config.AuthServiceConfig {
	if current == nil {
		current = config.NewDefaultAuthServiceConfig()
	}
	if patch == nil {
		return NormalizeAuthServiceConfig(current)
	}

	merged := *current
	if patch.SiteURL != nil {
		merged.SiteURL = *patch.SiteURL
	}
	if patch.AuthServiceBaseUrl != nil {
		merged.AuthServiceBaseUrl = *patch.AuthServiceBaseUrl
	}
	if patch.RedirectURLs != nil {
		merged.RedirectURLs = append([]string(nil), (*patch.RedirectURLs)...)
	}
	if patch.AllowNewUsers != nil {
		val := *patch.AllowNewUsers
		merged.AllowNewUsers = &val
	}
	if patch.ManualLinking != nil {
		val := *patch.ManualLinking
		merged.ManualLinking = &val
	}
	if patch.AnonymousSignIns != nil {
		val := *patch.AnonymousSignIns
		merged.AnonymousSignIns = &val
	}
	if patch.ConfirmEmail != nil {
		val := *patch.ConfirmEmail
		merged.ConfirmEmail = &val
	}
	if patch.MFAUpdateRequiredAAL != nil {
		merged.MFAUpdateRequiredAAL = *patch.MFAUpdateRequiredAAL
	}
	if patch.MaximumMfaFactors != nil {
		merged.MaximumMfaFactors = *patch.MaximumMfaFactors
	}
	if patch.MaximumMfaFactorValidationAttempts != nil {
		merged.MaximumMfaFactorValidationAttempts = *patch.MaximumMfaFactorValidationAttempts
	}
	if patch.EnableCaptcha != nil {
		val := *patch.EnableCaptcha
		merged.EnableCaptcha = &val
	}
	if patch.MaxTimeAllowedForAuthRequest != nil {
		merged.MaxTimeAllowedForAuthRequest = *patch.MaxTimeAllowedForAuthRequest
	}

	merged.SessionConfig = applySessionConfigPatch(merged.SessionConfig, patch.SessionConfig)
	merged.RatelimitConfig = applyRatelimitConfigPatch(merged.RatelimitConfig, patch.RatelimitConfig)
	merged.SecurityConfig = applySecurityConfigPatch(merged.SecurityConfig, patch.SecurityConfig)

	merged.JWTSecret = current.JWTSecret
	merged.AppSecret = current.AppSecret
	merged.SetUpdatedAt(current.UpdatedAt())

	return NormalizeAuthServiceConfig(&merged)
}

func mergeSessionConfig(current, next *config.SessionConfig) *config.SessionConfig {
	if current == nil {
		current = config.GetDefaultSessionConfig()
	}
	if next == nil {
		cloned := *current
		return &cloned
	}

	merged := *current
	if next.RefreshTokenReuseInterval != 0 {
		merged.RefreshTokenReuseInterval = next.RefreshTokenReuseInterval
	}
	if next.TimeBoxUserSessions != 0 {
		merged.TimeBoxUserSessions = next.TimeBoxUserSessions
	}
	if next.InactivityTimeout != 0 {
		merged.InactivityTimeout = next.InactivityTimeout
	}
	if next.AccessTokenTTL != 0 {
		merged.AccessTokenTTL = next.AccessTokenTTL
	}
	if next.RefreshTokenTTL != 0 {
		merged.RefreshTokenTTL = next.RefreshTokenTTL
	}
	if next.RevokeCompromisedRefreshTokens != current.RevokeCompromisedRefreshTokens {
		merged.RevokeCompromisedRefreshTokens = next.RevokeCompromisedRefreshTokens
	}
	if next.EnforceSingleSessionPerUser != current.EnforceSingleSessionPerUser {
		merged.EnforceSingleSessionPerUser = next.EnforceSingleSessionPerUser
	}
	return &merged
}

func applySessionConfigPatch(current *config.SessionConfig, patch *config.SessionConfigPatch) *config.SessionConfig {
	if current == nil {
		current = config.GetDefaultSessionConfig()
	}
	if patch == nil {
		cloned := *current
		return &cloned
	}

	merged := *current
	if patch.RevokeCompromisedRefreshTokens != nil {
		merged.RevokeCompromisedRefreshTokens = *patch.RevokeCompromisedRefreshTokens
	}
	if patch.RefreshTokenReuseInterval != nil {
		merged.RefreshTokenReuseInterval = *patch.RefreshTokenReuseInterval
	}
	if patch.EnforceSingleSessionPerUser != nil {
		merged.EnforceSingleSessionPerUser = *patch.EnforceSingleSessionPerUser
	}
	if patch.TimeBoxUserSessions != nil {
		merged.TimeBoxUserSessions = *patch.TimeBoxUserSessions
	}
	if patch.InactivityTimeout != nil {
		merged.InactivityTimeout = *patch.InactivityTimeout
	}
	if patch.AccessTokenTTL != nil {
		merged.AccessTokenTTL = *patch.AccessTokenTTL
	}
	if patch.RefreshTokenTTL != nil {
		merged.RefreshTokenTTL = *patch.RefreshTokenTTL
	}
	return &merged
}

func mergeRatelimitConfig(current, next *config.RatelimitConfig) *config.RatelimitConfig {
	if current == nil {
		current = config.GetDefaultRatelimitConfig()
	}
	if next == nil {
		cloned := *current
		return &cloned
	}

	merged := *current
	merged.EmailRateLimit = mergeRateLimit(merged.EmailRateLimit, next.EmailRateLimit)
	merged.SMSRateLimit = mergeRateLimit(merged.SMSRateLimit, next.SMSRateLimit)
	merged.TokenRefreshRateLimit = mergeRateLimit(merged.TokenRefreshRateLimit, next.TokenRefreshRateLimit)
	merged.TokenVerificationRateLimit = mergeRateLimit(merged.TokenVerificationRateLimit, next.TokenVerificationRateLimit)
	merged.AnonymousUsersRateLimit = mergeRateLimit(merged.AnonymousUsersRateLimit, next.AnonymousUsersRateLimit)
	merged.SignUpSignInRateLimit = mergeRateLimit(merged.SignUpSignInRateLimit, next.SignUpSignInRateLimit)
	merged.Web3SignUpSignInRateLimit = mergeRateLimit(merged.Web3SignUpSignInRateLimit, next.Web3SignUpSignInRateLimit)
	return &merged
}

func applyRatelimitConfigPatch(current *config.RatelimitConfig, patch *config.RatelimitConfigPatch) *config.RatelimitConfig {
	if current == nil {
		current = config.GetDefaultRatelimitConfig()
	}
	if patch == nil {
		cloned := *current
		return &cloned
	}

	merged := *current
	merged.EmailRateLimit = applyRateLimitPatch(merged.EmailRateLimit, patch.EmailRateLimit)
	merged.SMSRateLimit = applyRateLimitPatch(merged.SMSRateLimit, patch.SMSRateLimit)
	merged.TokenRefreshRateLimit = applyRateLimitPatch(merged.TokenRefreshRateLimit, patch.TokenRefreshRateLimit)
	merged.TokenVerificationRateLimit = applyRateLimitPatch(merged.TokenVerificationRateLimit, patch.TokenVerificationRateLimit)
	merged.AnonymousUsersRateLimit = applyRateLimitPatch(merged.AnonymousUsersRateLimit, patch.AnonymousUsersRateLimit)
	merged.SignUpSignInRateLimit = applyRateLimitPatch(merged.SignUpSignInRateLimit, patch.SignUpSignInRateLimit)
	merged.Web3SignUpSignInRateLimit = applyRateLimitPatch(merged.Web3SignUpSignInRateLimit, patch.Web3SignUpSignInRateLimit)
	return &merged
}

func mergeSecurityConfig(current, next *config.SecurityConfig) *config.SecurityConfig {
	if current == nil {
		current = config.GetDefaultSecurityConfig()
	}
	if next == nil {
		cloned := *current
		return &cloned
	}

	merged := *current
	if next.AALPolicy != (config.AALPolicy{}) {
		merged.AALPolicy = mergeAALPolicy(merged.AALPolicy, next.AALPolicy)
	}
	if next.PasswordUpdateConfig != (config.PasswordUpdateConfig{}) {
		merged.PasswordUpdateConfig = mergePasswordUpdateConfig(merged.PasswordUpdateConfig, next.PasswordUpdateConfig)
	}
	if next.PasswordStrengthConfig != (config.PasswordStrengthConfig{}) {
		merged.PasswordStrengthConfig = mergePasswordStrengthConfig(merged.PasswordStrengthConfig, next.PasswordStrengthConfig)
	}
	if next.EmailChangeConfig != (config.IdentityChangeConfig{}) {
		merged.EmailChangeConfig = mergeIdentityChangeConfig(merged.EmailChangeConfig, next.EmailChangeConfig)
	}
	if next.PhoneChangeConfig != (config.IdentityChangeConfig{}) {
		merged.PhoneChangeConfig = mergeIdentityChangeConfig(merged.PhoneChangeConfig, next.PhoneChangeConfig)
	}
	return &merged
}

func applySecurityConfigPatch(current *config.SecurityConfig, patch *config.SecurityConfigPatch) *config.SecurityConfig {
	if current == nil {
		current = config.GetDefaultSecurityConfig()
	}
	if patch == nil {
		cloned := *current
		return &cloned
	}

	merged := *current
	merged.AALPolicy = applyAALPolicyPatch(merged.AALPolicy, patch.AALPolicy)
	merged.PasswordUpdateConfig = applyPasswordUpdateConfigPatch(merged.PasswordUpdateConfig, patch.PasswordUpdateConfig)
	merged.PasswordStrengthConfig = applyPasswordStrengthConfigPatch(merged.PasswordStrengthConfig, patch.PasswordStrengthConfig)
	merged.EmailChangeConfig = applyIdentityChangeConfigPatch(merged.EmailChangeConfig, patch.EmailChangeConfig)
	merged.PhoneChangeConfig = applyIdentityChangeConfigPatch(merged.PhoneChangeConfig, patch.PhoneChangeConfig)
	return &merged
}

func mergeAALPolicy(current, next config.AALPolicy) config.AALPolicy {
	merged := current
	if next.AALTimeout > 0 {
		merged.AALTimeout = next.AALTimeout
	}
	if next.AllowDowngrade != current.AllowDowngrade {
		merged.AllowDowngrade = next.AllowDowngrade
	}
	return merged
}

func applyAALPolicyPatch(current config.AALPolicy, patch *config.AALPolicyPatch) config.AALPolicy {
	merged := current
	if patch == nil {
		return merged
	}
	if patch.AALTimeout != nil {
		merged.AALTimeout = *patch.AALTimeout
	}
	if patch.AllowDowngrade != nil {
		merged.AllowDowngrade = *patch.AllowDowngrade
	}
	return merged
}

func mergePasswordUpdateConfig(current, next config.PasswordUpdateConfig) config.PasswordUpdateConfig {
	merged := current
	if next.UpdateRequiredAAL != "" {
		merged.UpdateRequiredAAL = next.UpdateRequiredAAL
	}
	if next.RevokeOtherSessions != current.RevokeOtherSessions {
		merged.RevokeOtherSessions = next.RevokeOtherSessions
	}
	merged.RateLimit = mergeRateLimit(merged.RateLimit, next.RateLimit)
	return merged
}

func applyPasswordUpdateConfigPatch(current config.PasswordUpdateConfig, patch *config.PasswordUpdateConfigPatch) config.PasswordUpdateConfig {
	merged := current
	if patch == nil {
		return merged
	}
	if patch.UpdateRequiredAAL != nil {
		merged.UpdateRequiredAAL = *patch.UpdateRequiredAAL
	}
	if patch.RevokeOtherSessions != nil {
		merged.RevokeOtherSessions = *patch.RevokeOtherSessions
	}
	merged.RateLimit = applyRateLimitPatch(merged.RateLimit, patch.RateLimit)
	return merged
}

func mergePasswordStrengthConfig(current, next config.PasswordStrengthConfig) config.PasswordStrengthConfig {
	merged := current
	if next.MinScore > 0 {
		merged.MinScore = next.MinScore
	}
	return merged
}

func applyPasswordStrengthConfigPatch(current config.PasswordStrengthConfig, patch *config.PasswordStrengthConfigPatch) config.PasswordStrengthConfig {
	merged := current
	if patch == nil {
		return merged
	}
	if patch.MinScore != nil {
		merged.MinScore = *patch.MinScore
	}
	return merged
}

func mergeIdentityChangeConfig(current, next config.IdentityChangeConfig) config.IdentityChangeConfig {
	merged := current
	if next.RequiredAAL != "" {
		merged.RequiredAAL = next.RequiredAAL
	}
	if next.RequireCurrentValueConfirmation != current.RequireCurrentValueConfirmation {
		merged.RequireCurrentValueConfirmation = next.RequireCurrentValueConfirmation
	}
	merged.RateLimit = mergeRateLimit(merged.RateLimit, next.RateLimit)
	return merged
}

func applyIdentityChangeConfigPatch(current config.IdentityChangeConfig, patch *config.IdentityChangeConfigPatch) config.IdentityChangeConfig {
	merged := current
	if patch == nil {
		return merged
	}
	if patch.RequiredAAL != nil {
		merged.RequiredAAL = *patch.RequiredAAL
	}
	if patch.RequireCurrentValueConfirmation != nil {
		merged.RequireCurrentValueConfirmation = *patch.RequireCurrentValueConfirmation
	}
	merged.RateLimit = applyRateLimitPatch(merged.RateLimit, patch.RateLimit)
	return merged
}

func mergeRateLimit(current, next config.RateLimit) config.RateLimit {
	merged := current
	if next.MaxRequests > 0 {
		merged.MaxRequests = next.MaxRequests
	}
	if next.WindowDuration > 0 {
		merged.WindowDuration = next.WindowDuration
	}
	if next.Description != "" {
		merged.Description = next.Description
	}
	return merged
}

func applyRateLimitPatch(current config.RateLimit, patch *config.RateLimitPatch) config.RateLimit {
	merged := current
	if patch == nil {
		return merged
	}
	if patch.MaxRequests != nil {
		merged.MaxRequests = *patch.MaxRequests
	}
	if patch.WindowDuration != nil {
		merged.WindowDuration = *patch.WindowDuration
	}
	if patch.Description != nil {
		merged.Description = *patch.Description
	}
	return merged
}
