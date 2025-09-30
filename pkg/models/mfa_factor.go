package models

import (
	"encoding/json"
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

type MFAFactor struct {
	ID                 uint               `json:"id" gorm:"primaryKey;autoIncrement;not null"`
	UserID             uint               `json:"user_id" gorm:"not null;index"`
	FriendlyName       *string            `json:"friendly_name" gorm:"type:varchar(255)"`
	FactorType         types.FactorType   `json:"factor_type" gorm:"type:varchar(255);not null"`
	Status             types.FactorStatus `json:"status" gorm:"type:varchar(255);not null"`
	CreatedAt          time.Time          `json:"created_at" gorm:"not null"`
	UpdatedAt          time.Time          `json:"updated_at" gorm:"not null"`
	Secret             *string            `json:"-" gorm:"type:varchar(255)"`
	Phone              *string            `json:"phone" gorm:"type:varchar(255)"`
	LastChallengedAt   *time.Time         `json:"last_challenged_at" gorm:"uniqueIndex"`
	WebAuthnCredential *json.RawMessage   `json:"web_authn_credential"`
	WebAuthnAAGUID     *uint              `json:"web_authn_aaguid"`
	DomainCode         string             `json:"domain_code" gorm:"type:varchar(255)"`

	// Relationships
	User          *User          `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
	MFAChallenges []MFAChallenge `json:"mfa_challenges,omitempty" gorm:"foreignKey:FactorID"`
}
