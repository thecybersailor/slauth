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
	configBytes, _ := json.Marshal(instance.Config)
	json.Unmarshal(configBytes, cfg)

	cfg.JWTSecret = l.globalJWTSecret
	cfg.AppSecret = l.globalAppSecret

	return cfg
}

func (l *ConfigLoader) createDefaultInstance() *config.AuthServiceConfig {
	cfg := config.NewDefaultAuthServiceConfig()

	configBytes, _ := json.Marshal(cfg)
	var configMap models.JSONMap
	json.Unmarshal(configBytes, &configMap)

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
	configBytes, _ := json.Marshal(cfg)
	var configMap models.JSONMap
	json.Unmarshal(configBytes, &configMap)

	var instance models.AuthInstance
	err := l.db.Where("domain_code = ?", l.domainCode).First(&instance).Error

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
