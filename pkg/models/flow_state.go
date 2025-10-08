package models

import (
	"time"
)

type FlowState struct {
	ID                   uint       `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID               uint       `json:"user_id"`
	AuthCode             string     `json:"auth_code" gorm:"type:varchar(255);not null"`
	CodeChallengeMethod  string     `json:"code_challenge_method" gorm:"type:varchar(255);not null"` // USER-DEFINED type mapped to varchar
	CodeChallenge        string     `json:"code_challenge" gorm:"type:varchar(255);not null"`
	CodeVerifier         string     `json:"code_verifier" gorm:"type:varchar(255);not null"`
	ProviderType         string     `json:"provider_type" gorm:"type:varchar(255);not null"`
	ProviderAccessToken  *string    `json:"provider_access_token" gorm:"type:varchar(255)"`
	ProviderRefreshToken *string    `json:"provider_refresh_token" gorm:"type:varchar(255)"`
	RedirectURI          string     `json:"redirect_uri" gorm:"type:varchar(500)"`
	RedirectTo           string     `json:"redirect_to" gorm:"type:varchar(500)"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	AuthenticationMethod string     `json:"authentication_method" gorm:"type:varchar(255);not null"`
	AuthCodeIssuedAt     *time.Time `json:"auth_code_issued_at"`
	InstanceId           string     `json:"instance_id" gorm:"type:varchar(255)"`

	// Relationships
	SAMLRelayStates []SAMLRelayState `json:"saml_relay_states,omitempty" gorm:"foreignKey:FlowStateID"`
}
