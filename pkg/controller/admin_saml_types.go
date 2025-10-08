package controller

import (
	"encoding/json"
)

// ===== SAML Provider Management Types =====

// CreateSAMLProviderRequest represents the request to create a SAML provider
type CreateSAMLProviderRequest struct {
	Name    string `json:"name" binding:"required"`
	Enabled bool   `json:"enabled"`
}

// UpdateSAMLProviderRequest represents the request to update a SAML provider
type UpdateSAMLProviderRequest struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

// ListSAMLProvidersRequest represents the request to list SAML providers
type ListSAMLProvidersRequest struct {
	Page     int `form:"page"`
	PageSize int `form:"page_size"`
}

// SAMLProviderResponse represents a SAML provider in API responses
type SAMLProviderResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// SAMLConfigResponse represents SAML configuration in API responses
type SAMLConfigResponse struct {
	EntityID         string          `json:"entity_id"`
	MetadataURL      *string         `json:"metadata_url,omitempty"`
	NameIDFormat     *string         `json:"name_id_format,omitempty"`
	AttributeMapping json.RawMessage `json:"attribute_mapping,omitempty"`
}

// SAMLProviderDetailResponse represents detailed SAML provider information
type SAMLProviderDetailResponse struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Enabled    bool                `json:"enabled"`
	CreatedAt  string              `json:"created_at"`
	UpdatedAt  string              `json:"updated_at"`
	SAMLConfig *SAMLConfigResponse `json:"saml_config,omitempty"`
}

// ListSAMLProvidersResponse represents the response for listing SAML providers
type ListSAMLProvidersResponse struct {
	Providers []*SAMLProviderResponse `json:"providers,omitempty"`
	Total     int64                   `json:"total"`
	Page      int                     `json:"page"`
	PageSize  int                     `json:"page_size"`
}

// SAMLTestResponse represents the response for testing SAML provider
type SAMLTestResponse struct {
	Success         bool                     `json:"success"`
	Message         string                   `json:"message"`
	CertificateInfo *CertificateInfoResponse `json:"certificate_info,omitempty"`
}

// CertificateInfoResponse represents certificate information
type CertificateInfoResponse struct {
	ExpiresAt           string `json:"expires_at"`
	IssuedAt            string `json:"issued_at"`
	Subject             string `json:"subject"`
	Issuer              string `json:"issuer"`
	SerialNumber        string `json:"serial_number"`
	DaysUntilExpiration int    `json:"days_until_expiration"`
}

// ===== SAML Configuration Management Types =====

// CreateSAMLConfigRequest represents the request to create SAML configuration
type CreateSAMLConfigRequest struct {
	ProviderID       string          `json:"provider_id" binding:"required"`
	EntityID         string          `json:"entity_id" binding:"required"`
	MetadataXML      string          `json:"metadata_xml" binding:"required"`
	MetadataURL      *string         `json:"metadata_url,omitempty"`
	NameIDFormat     *string         `json:"name_id_format,omitempty"`
	AttributeMapping json.RawMessage `json:"attribute_mapping,omitempty"`
}

// UpdateSAMLConfigRequest represents the request to update SAML configuration
type UpdateSAMLConfigRequest struct {
	EntityID         *string         `json:"entity_id,omitempty"`
	MetadataXML      *string         `json:"metadata_xml,omitempty"`
	MetadataURL      *string         `json:"metadata_url,omitempty"`
	NameIDFormat     *string         `json:"name_id_format,omitempty"`
	AttributeMapping json.RawMessage `json:"attribute_mapping,omitempty"`
}

// ===== SSO Instance Management Types =====

// CreateSSOInstanceRequest represents the request to create SSO instance
type CreateSSOInstanceRequest struct {
	ProviderID string `json:"provider_id" binding:"required"`
	Instance   string `json:"instance" binding:"required"`
}

// SSOInstanceResponse represents SSO instance in API responses
type SSOInstanceResponse struct {
	ID         string `json:"id"`
	ProviderID string `json:"provider_id"`
	Instance   string `json:"instance"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// ListSSOInstancesRequest represents the request to list SSO instances
type ListSSOInstancesRequest struct {
	ProviderID string `form:"provider_id"`
	Page       int    `form:"page"`
	PageSize   int    `form:"page_size"`
}

// ListSSOInstancesResponse represents the response for listing SSO instances
type ListSSOInstancesResponse struct {
	Instances []*SSOInstanceResponse `json:"instances,omitempty"`
	Total     int64                  `json:"total"`
	Page      int                    `json:"page"`
	PageSize  int                    `json:"page_size"`
}

// ===== Certificate Management Types =====

// GenerateCertificateRequest represents the request to generate certificate
type GenerateCertificateRequest struct {
	EntityID  string `json:"entity_id" binding:"required"`
	ValidDays int    `json:"valid_days"`
	Overwrite bool   `json:"overwrite"`
}

// CertificateStatusResponse represents certificate status
type CertificateStatusResponse struct {
	Exists              bool     `json:"exists"`
	Valid               bool     `json:"valid"`
	ExpiresAt           *string  `json:"expires_at,omitempty"`
	IssuedAt            *string  `json:"issued_at,omitempty"`
	Subject             *string  `json:"subject,omitempty"`
	Issuer              *string  `json:"issuer,omitempty"`
	SerialNumber        *string  `json:"serial_number,omitempty"`
	DaysUntilExpiration *int     `json:"days_until_expiration,omitempty"`
	Errors              []string `json:"errors,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

// ===== Metadata Management Types =====

// GetMetadataResponse represents SP metadata response
type GetMetadataResponse struct {
	EntityID    string `json:"entity_id"`
	MetadataXML string `json:"metadata_xml"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"metadata_url"`
}
