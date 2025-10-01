package services

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

type ConfigLoader struct {
	db         *gorm.DB
	domainCode string

	cachedConfig *config.AuthServiceConfig
	cacheMutex   sync.RWMutex
	cachedAt     time.Time
	cacheTTL     time.Duration

	globalJWTSecret string
	globalAppSecret string
}

func NewConfigLoader(db *gorm.DB, domainCode, globalJWTSecret, globalAppSecret string) *ConfigLoader {
	return &ConfigLoader{
		db:              db,
		domainCode:      domainCode,
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

	err := l.db.Where("domain_code = ?", l.domainCode).First(&instance).Error
	if err == gorm.ErrRecordNotFound {
		return l.createDefaultInstance()
	}
	if err != nil {
		return config.NewDefaultAuthServiceConfig()
	}

	cfg := config.NewDefaultAuthServiceConfig()
	configBytes, err := json.Marshal(instance.Config)
	if err != nil {
		return config.NewDefaultAuthServiceConfig()
	}
	if err := json.Unmarshal(configBytes, cfg); err != nil {
		return config.NewDefaultAuthServiceConfig()
	}

	cfg.JWTSecret = l.globalJWTSecret
	cfg.AppSecret = l.globalAppSecret

	return cfg
}

func (l *ConfigLoader) createDefaultInstance() *config.AuthServiceConfig {
	cfg := config.NewDefaultAuthServiceConfig()

	configBytes, err := json.Marshal(cfg)
	if err != nil {
		cfg.JWTSecret = l.globalJWTSecret
		cfg.AppSecret = l.globalAppSecret
		return cfg
	}
	var configMap models.JSONMap
	if err := json.Unmarshal(configBytes, &configMap); err != nil {
		cfg.JWTSecret = l.globalJWTSecret
		cfg.AppSecret = l.globalAppSecret
		return cfg
	}

	instance := models.AuthInstance{
		DomainCode: l.domainCode,
		Config:     configMap,
	}

	result := l.db.Create(&instance)
	if result.Error != nil {

		cfg.JWTSecret = l.globalJWTSecret
		cfg.AppSecret = l.globalAppSecret
		return cfg
	}

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

	configBytes, err := json.Marshal(mergedConfig)
	if err != nil {
		return err
	}
	var configMap models.JSONMap
	if err := json.Unmarshal(configBytes, &configMap); err != nil {
		return err
	}

	var instance models.AuthInstance
	err = l.db.Where("domain_code = ?", l.domainCode).First(&instance).Error

	if err == gorm.ErrRecordNotFound {
		instance = models.AuthInstance{
			DomainCode: l.domainCode,
			Config:     configMap,
		}
		err = l.db.Create(&instance).Error
	} else {
		instance.Config = configMap
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
	// For boolean fields, always update since false is a valid value
	merged.AllowNewUsers = new.AllowNewUsers
	merged.ManualLinking = new.ManualLinking
	merged.AnonymousSignIns = new.AnonymousSignIns
	merged.ConfirmEmail = new.ConfirmEmail
	merged.EnableCaptcha = new.EnableCaptcha

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
	if new.SessionConfig != nil {
		merged.SessionConfig = new.SessionConfig
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
