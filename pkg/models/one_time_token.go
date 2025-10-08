package models

import (
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

type OneTimeToken struct {
	ID         uint                   `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID     *uint                  `json:"user_id" gorm:"index"` // Made optional for OTP scenarios
	TokenType  types.OneTimeTokenType `json:"token_type" gorm:"type:varchar(255);not null"`
	TokenHash  string                 `json:"-" gorm:"type:varchar(255);not null"`
	RelatesTo  string                 `json:"relates_to" gorm:"type:varchar(255);not null"`
	Email      *string                `json:"email" gorm:"type:varchar(255)"`   // For OTP scenarios
	Phone      *string                `json:"phone" gorm:"type:varchar(255)"`   // For OTP scenarios
	ExpiresAt  *time.Time             `json:"expires_at" gorm:"type:timestamp"` // For OTP expiry
	CreatedAt  time.Time              `json:"created_at" gorm:"type:timestamp;not null"`
	UpdatedAt  time.Time              `json:"updated_at" gorm:"type:timestamp;not null"`
	InstanceId string                 `json:"instance_id" gorm:"type:varchar(255)"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
}
