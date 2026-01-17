package models

import (
	"encoding/json"
	"time"
)

type SSOProvider struct {
	ID         uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Name       string    `json:"name" gorm:"type:varchar(255);not null"`
	Enabled    bool      `json:"enabled" gorm:"default:true"`
	InstanceId string    `json:"instance_id" gorm:"type:varchar(255)"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	SAMLProviders []SAMLProvider `json:"saml_providers,omitempty" gorm:"foreignKey:SSOProviderID"`
	SSOInstances  []SSOInstance  `json:"sso_instances,omitempty" gorm:"foreignKey:SSOProviderID"`
}

func (SSOProvider) TableName() string {
	return getTableName("sso_providers")
}

type SAMLProvider struct {
	ID               uint            `json:"id" gorm:"primaryKey;autoIncrement"`
	SSOProviderID    uint            `json:"sso_provider_id" gorm:"not null;index"`
	EntityID         string          `json:"entity_id" gorm:"type:varchar(512);not null;uniqueIndex"`
	MetadataXML      string          `json:"metadata_xml" gorm:"type:text;not null;"`
	MetadataURL      *string         `json:"metadata_url" gorm:"type:varchar(512)"`
	AttributeMapping json.RawMessage `json:"attribute_mapping"`
	NameIDFormat     *string         `json:"name_id_format" gorm:"type:varchar(255)"`
	InstanceId       string          `json:"instance_id" gorm:"type:varchar(255)"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

func (SAMLProvider) TableName() string {
	return getTableName("saml_providers")
}

type SSOInstance struct {
	ID            uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	SSOProviderID uint      `json:"sso_provider_id" gorm:"not null;index"`
	Instance      string    `json:"instance" gorm:"type:text;not null;check:length(instance) > 0"`
	InstanceId    string    `json:"instance_id" gorm:"type:varchar(255)"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (SSOInstance) TableName() string {
	return getTableName("sso_instances")
}
