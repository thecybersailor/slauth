package models

import (
	"time"
)

type MFAAMRClaim struct {
	ID                   uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	SessionID            uint      `json:"session_id" gorm:"not null;index"`
	CreatedAt            time.Time `json:"created_at" gorm:"not null"`
	UpdatedAt            time.Time `json:"updated_at" gorm:"not null"`
	AuthenticationMethod string    `json:"authentication_method" gorm:"type:varchar(255);not null"`
	InstanceId           string    `json:"instance_id" gorm:"type:varchar(255)"`

	// Relationships
	Session *Session `json:"session,omitempty" gorm:"foreignKey:SessionID;references:ID"`
}

func (MFAAMRClaim) TableName() string {
	return getTableName("mfa_amr_claims")
}
