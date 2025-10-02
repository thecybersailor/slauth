package models

import (
	"time"
)

type User struct {
	ID                       uint       `json:"id" gorm:"primaryKey;autoIncrement"`
	DomainCode               string     `json:"domain_code" gorm:"type:varchar(255);uniqueIndex:idx_users_email,priority:1;uniqueIndex:idx_users_phone,priority:1"`
	Email                    *string    `json:"email" gorm:"type:varchar(255);uniqueIndex:idx_users_email,priority:2"`
	EncryptedPassword        *string    `json:"-" gorm:"column:encrypted_password;type:varchar(255)"`
	EmailConfirmedAt         *time.Time `json:"email_confirmed_at"`
	InvitedAt                *time.Time `json:"invited_at"`
	ConfirmationToken        *string    `json:"-" gorm:"type:varchar(255)"`
	ConfirmationSentAt       *time.Time `json:"confirmation_sent_at"`
	RecoveryToken            *string    `json:"-" gorm:"type:varchar(255)"`
	RecoverySentAt           *time.Time `json:"recovery_sent_at"`
	EmailChangeTokenNew      *string    `json:"-" gorm:"type:varchar(255)"`
	EmailChange              *string    `json:"email_change" gorm:"type:varchar(255)"`
	EmailChangeSentAt        *time.Time `json:"email_change_sent_at"`
	LastSignInAt             *time.Time `json:"last_sign_in_at"`
	RawUserMetaData          *JSON      `json:"user_metadata"`
	RawAppMetaData           *JSON      `json:"app_metadata"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	Phone                    *string    `json:"phone" gorm:"type:varchar(255);uniqueIndex:idx_users_phone,priority:2"`
	PhoneConfirmedAt         *time.Time `json:"phone_confirmed_at"`
	PhoneChange              *string    `json:"phone_change" gorm:"type:varchar(255)"`
	PhoneChangeToken         *string    `json:"-" gorm:"type:varchar(255);default:''"`
	PhoneChangeSentAt        *time.Time `json:"phone_change_sent_at"`
	ConfirmedAt              *time.Time `json:"confirmed_at"`
	EmailChangeTokenCurrent  *string    `json:"-" gorm:"type:varchar(255);default:''"`
	EmailChangeConfirmStatus *int16     `json:"email_change_confirm_status" gorm:"type:smallint;default:0;check:email_change_confirm_status >= 0 AND email_change_confirm_status <= 2"`
	BannedUntil              *time.Time `json:"banned_until"`
	ReauthenticationToken    *string    `json:"-" gorm:"type:varchar(255);default:''"`
	ReauthenticationSentAt   *time.Time `json:"reauthentication_sent_at"`
	IsSSOUser                bool       `json:"is_sso_user" gorm:"default:false;not null"`
	DeletedAt                *time.Time `json:"deleted_at"`
	IsAnonymous              bool       `json:"is_anonymous" gorm:"default:false;not null"`

	// Relationships
	Identities    []Identity     `json:"identities,omitempty" gorm:"foreignKey:UserID"`
	Sessions      []Session      `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
	MFAFactors    []MFAFactor    `json:"mfa_factors,omitempty" gorm:"foreignKey:UserID"`
	OneTimeTokens []OneTimeToken `json:"one_time_tokens,omitempty" gorm:"foreignKey:UserID"`
}
