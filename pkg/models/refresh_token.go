package models

import (
	"time"
)

type RefreshToken struct {
	ID         uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Token      string    `json:"token" gorm:"type:varchar(255);uniqueIndex"`
	UserID     uint      `json:"user_id"`
	Revoked    bool      `json:"revoked"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Parent     *uint     `json:"parent"`
	SessionID  uint      `json:"session_id"`
	InstanceId string    `json:"instance_id" gorm:"type:varchar(255)"`

	// Relationships
	Session *Session `json:"session,omitempty" gorm:"foreignKey:SessionID;references:ID"`
}

func (RefreshToken) TableName() string {
	return getTableName("refresh_tokens")
}
