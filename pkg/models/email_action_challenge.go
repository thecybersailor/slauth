package models

import "time"

type EmailActionChallenge struct {
	ID                  string     `json:"id" gorm:"primaryKey;type:varchar(64)"`
	InstanceId          string     `json:"instance_id" gorm:"type:varchar(255);not null;index:idx_email_action_lookup,priority:1"`
	Purpose             string     `json:"purpose" gorm:"type:varchar(64);not null;index:idx_email_action_lookup,priority:2"`
	UserID              *uint      `json:"user_id,omitempty" gorm:"index"`
	SessionID           *uint      `json:"session_id,omitempty" gorm:"index"`
	Email               string     `json:"email" gorm:"type:varchar(255);not null;index"`
	OriginalEmail       string     `json:"original_email,omitempty" gorm:"type:varchar(255)"`
	SecretDigest        string     `json:"-" gorm:"type:varchar(255);not null"`
	PendingPasswordHash *string    `json:"-" gorm:"type:varchar(255)"`
	CredentialDigest    string     `json:"-" gorm:"type:varchar(255)"`
	Attempts            int        `json:"attempts" gorm:"not null;default:0"`
	ExpiresAt           time.Time  `json:"expires_at" gorm:"type:timestamp;not null;index"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty" gorm:"type:timestamp;index"`
	LastSentAt          time.Time  `json:"last_sent_at" gorm:"type:timestamp;not null"`
	CreatedAt           time.Time  `json:"created_at" gorm:"type:timestamp;not null"`
	UpdatedAt           time.Time  `json:"updated_at" gorm:"type:timestamp;not null"`

	User *User `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
}

func (EmailActionChallenge) TableName() string {
	return getTableName("email_action_challenges")
}
