package models

import (
	"encoding/json"
	"time"
)

type SSOProvider struct {
	ID         uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Name       string    `json:"name" gorm:"type:varchar(255);not null"`
	Enabled    bool      `json:"enabled" gorm:"default:true"`
	DomainCode string    `json:"domain_code" gorm:"type:varchar(255)"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	SAMLProviders []SAMLProvider `json:"saml_providers,omitempty" gorm:"foreignKey:SSOProviderID"`
	SSODomains    []SSODomain    `json:"sso_domains,omitempty" gorm:"foreignKey:SSOProviderID"`
}

type SAMLProvider struct {
	ID               uint            `json:"id" gorm:"primaryKey;autoIncrement"`
	SSOProviderID    uint            `json:"sso_provider_id" gorm:"not null;index"`
	EntityID         uint            `json:"entity_id" gorm:"not null;uniqueIndex"`
	MetadataXML      string          `json:"metadata_xml" gorm:"type:text;not null;"`
	MetadataURL      *string         `json:"metadata_url" gorm:"type:varchar(512)"`
	AttributeMapping json.RawMessage `json:"attribute_mapping"`
	NameIDFormat     *string         `json:"name_id_format" gorm:"type:varchar(255)"`
	DomainCode       string          `json:"domain_code" gorm:"type:varchar(255)"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type SSODomain struct {
	ID            uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	SSOProviderID uint      `json:"sso_provider_id" gorm:"not null;index"`
	Domain        string    `json:"domain" gorm:"type:text;not null;check:length(domain) > 0"`
	DomainCode    string    `json:"domain_code" gorm:"type:varchar(255)"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
