package models

import (
	"encoding/json"
	"strings"
	"time"

	"gorm.io/gorm"
)

type Identity struct {
	ID           uint            `json:"id" gorm:"primaryKey;autoIncrement"`
	ProviderID   string          `json:"provider_id" gorm:"type:varchar(255);not null"`
	UserID       uint            `json:"user_id" gorm:"not null;index"`
	IdentityData json.RawMessage `json:"identity_data" gorm:"not null"`
	Provider     string          `json:"provider" gorm:"type:varchar(255);not null"`
	LastSignInAt *time.Time      `json:"last_sign_in_at"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	Email        *string         `json:"email" gorm:"type:varchar(255)"`
	InstanceId   string          `json:"instance_id" gorm:"type:varchar(255)"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
}

func (i *Identity) BeforeCreate(tx *gorm.DB) error {
	if i.Email == nil {
		i.Email = new(string)
		*i.Email = strings.ToLower(*i.Email)
	}
	return nil
}
