package models

import (
	"encoding/json"
	"time"
)

type MFAChallenge struct {
	ID                  uint             `json:"id" gorm:"primaryKey;autoIncrement;not null"`
	FactorID            uint             `json:"factor_id" gorm:"not null;index"`
	CreatedAt           time.Time        `json:"created_at" gorm:"not null"`
	VerifiedAt          *time.Time       `json:"verified_at"`
	IPAddress           string           `json:"ip_address" gorm:"type:varchar(200);not null"`
	OTPCode             *string          `json:"-" gorm:"column:otp_code;type:text"`
	WebAuthnSessionData *json.RawMessage `json:"web_authn_session_data"`
	DomainCode          string           `json:"domain_code" gorm:"type:varchar(255)"`

	// Relationships
	Factor *MFAFactor `json:"factor,omitempty" gorm:"foreignKey:FactorID;references:ID"`
}
