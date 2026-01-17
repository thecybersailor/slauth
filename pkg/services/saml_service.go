package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/providers/identities/saml"
	"gorm.io/gorm"
)

// Type aliases for convenience
type CertService = saml.CertService
type CertificateValidation = saml.CertificateValidation

// NewCertService creates a new certificate service
func NewCertService(certPath, keyPath string) *CertService {
	return saml.NewCertService(certPath, keyPath)
}

// SAMLService handles SAML SSO operations
type SAMLService struct {
	db         *gorm.DB
	instanceId string
}

// NewSAMLService creates a new SAML service
func NewSAMLService(db *gorm.DB, instanceId string) *SAMLService {
	return &SAMLService{
		db:         db,
		instanceId: instanceId,
	}
}

// FindSSOProviderByInstance finds SSO provider by instance
func (s *SAMLService) FindSSOProviderByInstance(ctx context.Context, instance string) (*SSOProvider, error) {
	var ssoProvider models.SSOProvider

	// Get table names dynamically
	ssoProviderTable := models.SSOProvider{}.TableName()
	ssoInstanceTable := models.SSOInstance{}.TableName()

	// Find SSO provider by instance
	err := s.db.WithContext(ctx).
		Table(ssoProviderTable + " AS sp").
		Joins("JOIN ? AS si ON si.sso_provider_id = sp.id",
			gorm.Expr(ssoInstanceTable)).
		Where("si.instance = ? AND sp.instance_id = ? AND sp.enabled = ?",
			instance, s.instanceId, true).
		First(&ssoProvider).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, consts.SSO_PROVIDER_NOT_FOUND
		}
		return nil, consts.UNEXPECTED_FAILURE
	}

	return NewSSOProvider(&ssoProvider)
}

// FindSSOProviderByID finds SSO provider by hashid
func (s *SAMLService) FindSSOProviderByID(ctx context.Context, providerHashID string) (*SSOProvider, error) {
	// Decode hashid to database ID
	providerID, err := GetSSOProviderIDFromHashID(providerHashID)
	if err != nil {
		return nil, fmt.Errorf("invalid provider ID: %w", err)
	}

	var ssoProvider models.SSOProvider
	err = s.db.WithContext(ctx).
		Where("id = ? AND instance_id = ? AND enabled = ?", providerID, s.instanceId, true).
		First(&ssoProvider).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("SSO provider not found")
		}
		return nil, fmt.Errorf("failed to find SSO provider: %w", err)
	}

	return NewSSOProvider(&ssoProvider)
}

// GetSAMLProvider gets SAML provider configuration for SSO provider
func (s *SAMLService) GetSAMLProvider(ctx context.Context, ssoProvider *SSOProvider) (*SAMLProvider, error) {
	var samlProvider models.SAMLProvider

	err := s.db.WithContext(ctx).
		Where("sso_provider_id = ? AND instance_id = ?", ssoProvider.ID, s.instanceId).
		First(&samlProvider).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("SAML configuration not found for provider")
		}
		return nil, fmt.Errorf("failed to get SAML provider: %w", err)
	}

	return NewSAMLProvider(&samlProvider)
}

// CreateSAMLProvider creates a SAML identity provider instance
func (s *SAMLService) CreateSAMLProvider(ctx context.Context, samlConfig *SAMLProvider, certService *saml.CertService) (*saml.SAMLProvider, error) {
	// Load certificate
	certInfo, err := certService.LoadCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Parse attribute mapping
	var attributeMapping map[string]string
	if len(samlConfig.AttributeMapping) > 0 {
		if err := json.Unmarshal(samlConfig.AttributeMapping, &attributeMapping); err != nil {
			return nil, fmt.Errorf("failed to parse attribute mapping: %w", err)
		}
	}

	// Set default NameID format if not provided
	nameIDFormat := "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	if samlConfig.NameIDFormat != nil {
		nameIDFormat = *samlConfig.NameIDFormat
	}

	// Create SAML provider configuration
	config := &saml.SAMLProviderConfig{
		EntityID:         samlConfig.EntityID,
		MetadataXML:      samlConfig.MetadataXML,
		MetadataURL:      samlConfig.MetadataURL,
		NameIDFormat:     nameIDFormat,
		AttributeMapping: attributeMapping,
		InstanceId:       samlConfig.InstanceId,
		SPEntityID:       fmt.Sprintf("https://auth.example.com/saml/metadata/%s", samlConfig.HashID),
		ACSURL:           fmt.Sprintf("https://auth.example.com/sso/callback/%s", samlConfig.HashID),
		Certificate:      certInfo.Certificate,
		PrivateKey:       certInfo.PrivateKey,
	}

	provider, err := saml.NewSAMLProvider(config)
	if err != nil {
		return nil, err
	}

	samlProvider, ok := provider.(*saml.SAMLProvider)
	if !ok {
		return nil, fmt.Errorf("failed to cast to SAML provider")
	}

	return samlProvider, nil
}

// CreateRelayState creates and stores SAML relay state
func (s *SAMLService) CreateRelayState(ctx context.Context, ssoProviderID uint, requestID string, options *SAMLRelayStateOptions) (*models.SAMLRelayState, error) {
	relayState := &models.SAMLRelayState{
		SSOProviderID: ssoProviderID,
		RequestID:     requestID,
		ForEmail:      options.ForEmail,
		RedirectTo:    options.RedirectTo,
		InstanceId:    s.instanceId,
	}

	if err := s.db.WithContext(ctx).Create(relayState).Error; err != nil {
		return nil, fmt.Errorf("failed to create relay state: %w", err)
	}

	return relayState, nil
}

// GetRelayState retrieves SAML relay state by request ID
func (s *SAMLService) GetRelayState(ctx context.Context, requestID string) (*models.SAMLRelayState, error) {
	var relayState models.SAMLRelayState

	err := s.db.WithContext(ctx).
		Where("request_id = ? AND instance_id = ?", requestID, s.instanceId).
		First(&relayState).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("relay state not found")
		}
		return nil, fmt.Errorf("failed to get relay state: %w", err)
	}

	return &relayState, nil
}

// DeleteRelayState deletes SAML relay state
func (s *SAMLService) DeleteRelayState(ctx context.Context, requestID string) error {
	err := s.db.WithContext(ctx).
		Where("request_id = ? AND instance_id = ?", requestID, s.instanceId).
		Delete(&models.SAMLRelayState{}).Error

	if err != nil {
		return fmt.Errorf("failed to delete relay state: %w", err)
	}

	return nil
}

// SAMLRelayStateOptions contains options for creating relay state
type SAMLRelayStateOptions struct {
	ForEmail   *string
	RedirectTo *string
}

// ListSSOProviders lists all SSO providers for the instance
func (s *SAMLService) ListSSOProviders(ctx context.Context, page, pageSize int) ([]*SSOProvider, int64, error) {
	var providers []models.SSOProvider
	var total int64

	// Get total count
	if err := s.db.WithContext(ctx).Model(&models.SSOProvider{}).
		Where("instance_id = ?", s.instanceId).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count SSO providers: %w", err)
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	if err := s.db.WithContext(ctx).
		Where("instance_id = ?", s.instanceId).
		Offset(offset).Limit(pageSize).
		Find(&providers).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list SSO providers: %w", err)
	}

	// Convert to objects
	result := make([]*SSOProvider, len(providers))
	for i, provider := range providers {
		obj, err := NewSSOProvider(&provider)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create SSO provider object: %w", err)
		}
		result[i] = obj
	}

	return result, total, nil
}

// CreateSSOProvider creates a new SSO provider
func (s *SAMLService) CreateSSOProvider(ctx context.Context, name string, enabled bool) (*SSOProvider, error) {
	provider := &models.SSOProvider{
		Name:       name,
		Enabled:    enabled,
		InstanceId: s.instanceId,
	}

	if err := s.db.WithContext(ctx).Create(provider).Error; err != nil {
		return nil, fmt.Errorf("failed to create SSO provider: %w", err)
	}

	return NewSSOProvider(provider)
}

// UpdateSSOProvider updates an existing SSO provider
func (s *SAMLService) UpdateSSOProvider(ctx context.Context, providerHashID string, updates map[string]interface{}) (*SSOProvider, error) {
	// Decode hashid to database ID
	providerID, err := GetSSOProviderIDFromHashID(providerHashID)
	if err != nil {
		return nil, fmt.Errorf("invalid provider ID: %w", err)
	}

	// Add instance code filter to updates
	updates["instance_id"] = s.instanceId

	if err := s.db.WithContext(ctx).Model(&models.SSOProvider{}).
		Where("id = ? AND instance_id = ?", providerID, s.instanceId).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update SSO provider: %w", err)
	}

	// Get updated provider
	var provider models.SSOProvider
	if err := s.db.WithContext(ctx).Where("id = ?", providerID).First(&provider).Error; err != nil {
		return nil, fmt.Errorf("failed to get updated provider: %w", err)
	}

	return NewSSOProvider(&provider)
}

// DeleteSSOProvider deletes an SSO provider
func (s *SAMLService) DeleteSSOProvider(ctx context.Context, providerHashID string) error {
	// Decode hashid to database ID
	providerID, err := GetSSOProviderIDFromHashID(providerHashID)
	if err != nil {
		return fmt.Errorf("invalid provider ID: %w", err)
	}

	if err := s.db.WithContext(ctx).
		Where("id = ? AND instance_id = ?", providerID, s.instanceId).
		Delete(&models.SSOProvider{}).Error; err != nil {
		return fmt.Errorf("failed to delete SSO provider: %w", err)
	}

	return nil
}

type SSOProvider struct {
	*models.SSOProvider
	HashID string `json:"hashid"`
}

func (sp *SSOProvider) GetModel() *models.SSOProvider {
	return sp.SSOProvider
}

type SAMLProvider struct {
	*models.SAMLProvider
	HashID string `json:"hashid"`
}

func (smp *SAMLProvider) GetModel() *models.SAMLProvider {
	return smp.SAMLProvider
}
