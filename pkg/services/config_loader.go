package services

import (
	"sync"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

type ConfigLoader struct {
	db         *gorm.DB
	instanceId string

	cachedConfig *config.AuthServiceConfig
	cacheMutex   sync.RWMutex
	cachedAt     time.Time
	cacheTTL     time.Duration

	globalJWTSecret string
	globalAppSecret string
}

func NewConfigLoader(db *gorm.DB, instanceId, globalJWTSecret, globalAppSecret string) *ConfigLoader {
	return &ConfigLoader{
		db:              db,
		instanceId:      instanceId,
		globalJWTSecret: globalJWTSecret,
		globalAppSecret: globalAppSecret,
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

	// AfterFind hook automatically unmarshals Config to ConfigData
	cfg := instance.ConfigData
	if cfg == nil {
		return config.NewDefaultAuthServiceConfig()
	}

	// Set UpdatedAt from database to config
	cfg.SetUpdatedAt(instance.UpdatedAt)

	cfg.JWTSecret = l.globalJWTSecret
	cfg.AppSecret = l.globalAppSecret

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
		cfg.JWTSecret = l.globalJWTSecret
		cfg.AppSecret = l.globalAppSecret
		return cfg
	}

	// Set UpdatedAt from created instance
	cfg.SetUpdatedAt(instance.UpdatedAt)

	cfg.JWTSecret = l.globalJWTSecret
	cfg.AppSecret = l.globalAppSecret

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
	mergedConfig := l.mergeConfigs(currentConfig, cfg)

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

// mergeConfigs merges new config with current config, preserving existing values for unspecified fields
func (l *ConfigLoader) mergeConfigs(current, new *config.AuthServiceConfig) *config.AuthServiceConfig {
	merged := &config.AuthServiceConfig{}

	// Copy current config as base
	*merged = *current

	// Override with new values
	// For boolean pointer fields, only update if not nil
	if new.AllowNewUsers != nil {
		merged.AllowNewUsers = new.AllowNewUsers
	}
	if new.ManualLinking != nil {
		merged.ManualLinking = new.ManualLinking
	}
	if new.AnonymousSignIns != nil {
		merged.AnonymousSignIns = new.AnonymousSignIns
	}
	if new.ConfirmEmail != nil {
		merged.ConfirmEmail = new.ConfirmEmail
	}
	if new.EnableCaptcha != nil {
		merged.EnableCaptcha = new.EnableCaptcha
	}

	// For string fields, only update if not empty
	if new.SiteURL != "" {
		merged.SiteURL = new.SiteURL
	}
	if new.AuthServiceBaseUrl != "" {
		merged.AuthServiceBaseUrl = new.AuthServiceBaseUrl
	}
	if new.RedirectURLs != nil {
		merged.RedirectURLs = new.RedirectURLs
	}
	if new.MFAUpdateRequiredAAL != "" {
		merged.MFAUpdateRequiredAAL = new.MFAUpdateRequiredAAL
	}

	// For numeric fields, only update if > 0
	if new.MaximumMfaFactors > 0 {
		merged.MaximumMfaFactors = new.MaximumMfaFactors
	}
	if new.MaximumMfaFactorValidationAttempts > 0 {
		merged.MaximumMfaFactorValidationAttempts = new.MaximumMfaFactorValidationAttempts
	}
	if new.MaxTimeAllowedForAuthRequest > 0 {
		merged.MaxTimeAllowedForAuthRequest = new.MaxTimeAllowedForAuthRequest
	}

	// Merge SessionConfig fields instead of replacing the whole object
	if new.SessionConfig != nil {
		if merged.SessionConfig == nil {
			merged.SessionConfig = config.GetDefaultSessionConfig()
		}
		// Only update non-zero values
		if new.SessionConfig.RefreshTokenReuseInterval != 0 {
			merged.SessionConfig.RefreshTokenReuseInterval = new.SessionConfig.RefreshTokenReuseInterval
		}
		if new.SessionConfig.TimeBoxUserSessions != 0 {
			merged.SessionConfig.TimeBoxUserSessions = new.SessionConfig.TimeBoxUserSessions
		}
		if new.SessionConfig.InactivityTimeout != 0 {
			merged.SessionConfig.InactivityTimeout = new.SessionConfig.InactivityTimeout
		}
		if new.SessionConfig.AccessTokenTTL != 0 {
			merged.SessionConfig.AccessTokenTTL = new.SessionConfig.AccessTokenTTL
		}
		if new.SessionConfig.RefreshTokenTTL != 0 {
			merged.SessionConfig.RefreshTokenTTL = new.SessionConfig.RefreshTokenTTL
		}
		// Always update boolean fields (false is a valid value)
		merged.SessionConfig.RevokeCompromisedRefreshTokens = new.SessionConfig.RevokeCompromisedRefreshTokens
		merged.SessionConfig.EnforceSingleSessionPerUser = new.SessionConfig.EnforceSingleSessionPerUser
	}

	if new.RatelimitConfig != nil {
		merged.RatelimitConfig = new.RatelimitConfig
	}
	if new.SecurityConfig != nil {
		merged.SecurityConfig = new.SecurityConfig
	}

	// Always preserve secrets
	merged.JWTSecret = current.JWTSecret
	merged.AppSecret = current.AppSecret

	return merged
}
