package models

import (
	"encoding/json"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"gorm.io/gorm"
)

type AuthInstance struct {
	ID         uint            `gorm:"primaryKey" json:"id"`
	DomainCode string          `gorm:"uniqueIndex;not null;size:255" json:"domain_code"`
	Config     json.RawMessage `gorm:"type:json;not null" json:"config"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`

	// Transient field for working with typed config
	ConfigData *config.AuthServiceConfig `gorm:"-" json:"-"`
}

// BeforeSave marshals ConfigData to Config JSON before saving
func (a *AuthInstance) BeforeSave(tx *gorm.DB) error {
	if a.ConfigData != nil {
		data, err := json.Marshal(a.ConfigData)
		if err != nil {
			return err
		}
		a.Config = data
	}
	return nil
}

// AfterFind unmarshals Config JSON to ConfigData after loading
func (a *AuthInstance) AfterFind(tx *gorm.DB) error {
	if len(a.Config) > 0 {
		a.ConfigData = &config.AuthServiceConfig{}
		return json.Unmarshal(a.Config, a.ConfigData)
	}
	return nil
}

func (AuthInstance) TableName() string {
	return "auth_instances"
}
