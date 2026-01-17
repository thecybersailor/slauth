package models

import (
	"time"
)

type SAMLRelayState struct {
	ID            uint       `json:"id" gorm:"primaryKey;autoIncrement"`
	SSOProviderID uint       `json:"sso_provider_id" gorm:"not null;index"`
	RequestID     string     `json:"request_id" gorm:"type:varchar(255);not null"`
	ForEmail      *string    `json:"for_email" gorm:"type:varchar(255)"`
	RedirectTo    *string    `json:"redirect_to" gorm:"type:varchar(255)"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	FlowStateID   uint       `json:"flow_state_id"`
	InstanceId    string     `json:"instance_id" gorm:"type:varchar(255)"`
	FlowState     *FlowState `json:"flow_state,omitempty" gorm:"foreignKey:FlowStateID;references:ID"`
}

func (SAMLRelayState) TableName() string {
	return getTableName("saml_relay_states")
}
