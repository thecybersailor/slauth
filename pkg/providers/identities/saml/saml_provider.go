package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/thecybersailor/slauth/pkg/types"
)

// SAMLProvider implements types.IdentityProvider for SAML authentication
type SAMLProvider struct {
	entityID         string
	metadataXML      string
	metadataURL      *string
	nameIDFormat     string
	attributeMapping map[string]string
	serviceProvider  *samlsp.Middleware
	instanceId       string
}

// SAMLProviderConfig represents SAML provider configuration
type SAMLProviderConfig struct {
	EntityID         string            `json:"entity_id"`
	MetadataXML      string            `json:"metadata_xml"`
	MetadataURL      *string           `json:"metadata_url"`
	NameIDFormat     string            `json:"name_id_format"`
	AttributeMapping map[string]string `json:"attribute_mapping"`
	InstanceId       string            `json:"instance_id"`

	// Service Provider configuration
	SPEntityID  string            `json:"sp_entity_id"`
	ACSURL      string            `json:"acs_url"`
	Certificate *x509.Certificate `json:"-"`
	PrivateKey  *rsa.PrivateKey   `json:"-"`
}

// NewSAMLProvider creates a new SAML identity provider
func NewSAMLProvider(config *SAMLProviderConfig) (types.IdentityProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.EntityID == "" {
		return nil, fmt.Errorf("entity_id is required")
	}

	if config.MetadataXML == "" {
		return nil, fmt.Errorf("metadata_xml is required")
	}

	// Parse IdP metadata
	idpMetadata := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(config.MetadataXML), idpMetadata); err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata: %w", err)
	}

	// Create service provider
	sp, err := createServiceProvider(config, idpMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create service provider: %w", err)
	}

	// Set default attribute mapping if not provided
	attrMapping := config.AttributeMapping
	if attrMapping == nil {
		attrMapping = getDefaultAttributeMapping()
	}

	// Set default NameID format if not provided
	nameIDFormat := config.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = string(saml.EmailAddressNameIDFormat)
	}

	return &SAMLProvider{
		entityID:         config.EntityID,
		metadataXML:      config.MetadataXML,
		metadataURL:      config.MetadataURL,
		nameIDFormat:     nameIDFormat,
		attributeMapping: attrMapping,
		serviceProvider:  sp,
		instanceId:       config.InstanceId,
	}, nil
}

// GetName returns the provider name
func (p *SAMLProvider) GetName() string {
	return "saml"
}

// Authorize generates SAML AuthnRequest and returns redirect URL
func (p *SAMLProvider) Authorize(options json.RawMessage) (*types.OAuthConfig, error) {
	// Parse options if provided
	var opts struct {
		RelayState string `json:"relay_state"`
		RedirectTo string `json:"redirect_to"`
		ForceAuthn bool   `json:"force_authn"`
	}

	if len(options) > 0 {
		if err := json.Unmarshal(options, &opts); err != nil {
			return nil, fmt.Errorf("invalid options: %w", err)
		}
	}

	// Generate AuthnRequest URL
	// Note: In a real implementation, this would generate the actual SAML AuthnRequest
	// and return the IdP's SSO URL with the request

	return &types.OAuthConfig{
		Config: map[string]any{
			"sso_url":     p.getIdPSSOURL(),
			"relay_state": opts.RelayState,
			"entity_id":   p.entityID,
		},
		FlowType: types.FlowTypeAuthCode, // SAML uses authorization code flow pattern
	}, nil
}

// ValidateCredential validates SAML Response (not typically used for SAML)
func (p *SAMLProvider) ValidateCredential(ctx context.Context, credential json.RawMessage) (*types.OAuthResponse, error) {
	return nil, fmt.Errorf("SAML authentication should use ExchangeCodeForToken method")
}

// ExchangeCodeForToken processes SAML Response and extracts user information
func (p *SAMLProvider) ExchangeCodeForToken(ctx context.Context, samlResponse string, redirectURI string) (*types.OAuthResponse, error) {
	if samlResponse == "" {
		return nil, fmt.Errorf("saml_response is required")
	}

	// Parse and validate SAML Response
	// Note: This is a simplified implementation. In production, you would need to
	// properly handle the HTTP request and parse the SAML response correctly
	possibleRequestIDs := []string{} // In real implementation, this would be tracked
	requestURL := url.URL{}          // In real implementation, this would be the actual request URL
	assertion, err := p.serviceProvider.ServiceProvider.ParseXMLResponse([]byte(samlResponse), possibleRequestIDs, requestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Extract user information from SAML assertion
	userInfo, err := p.extractUserInfo(assertion)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user info: %w", err)
	}

	// Create token info (SAML doesn't have traditional tokens)
	tokenInfo := &types.OAuthTokenInfo{
		AccessToken: samlResponse, // Store the SAML response as "token"
		TokenType:   "SAML",
		ExpiresIn:   3600, // Default expiration
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

// createServiceProvider creates and configures the SAML Service Provider
func createServiceProvider(config *SAMLProviderConfig, idpMetadata *saml.EntityDescriptor) (*samlsp.Middleware, error) {
	if config.Certificate == nil || config.PrivateKey == nil {
		return nil, fmt.Errorf("certificate and private key are required")
	}

	rootURL, err := url.Parse(config.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ACS URL: %w", err)
	}

	// Remove the path to get the root URL
	rootURL.Path = ""

	samlSP, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         config.PrivateKey,
		Certificate: config.Certificate,
		IDPMetadata: idpMetadata,
		EntityID:    config.SPEntityID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML SP: %w", err)
	}

	return samlSP, nil
}

// extractUserInfo extracts user information from SAML assertion using attribute mapping
func (p *SAMLProvider) extractUserInfo(assertion *saml.Assertion) (*types.ExternalUserInfo, error) {
	if assertion == nil {
		return nil, fmt.Errorf("assertion cannot be nil")
	}

	userInfo := &types.ExternalUserInfo{
		Metadata: make(map[string]any),
	}

	// Extract NameID as the primary identifier
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		userInfo.UID = assertion.Subject.NameID.Value

		// If NameID format is email, use it as email
		if assertion.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) {
			userInfo.Email = assertion.Subject.NameID.Value
		}
	}

	// Extract attributes using attribute mapping
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) == 0 {
				continue
			}

			attrValue := attr.Values[0].Value

			// Map SAML attributes to user info fields
			switch p.attributeMapping[attr.Name] {
			case "email":
				userInfo.Email = attrValue
			case "name":
				userInfo.Name = attrValue
			case "given_name":
				userInfo.Metadata["given_name"] = attrValue
			case "family_name":
				userInfo.Metadata["family_name"] = attrValue
			case "department":
				userInfo.Metadata["department"] = attrValue
			default:
				// Store unmapped attributes in metadata
				userInfo.Metadata[attr.Name] = attrValue
			}
		}
	}

	// Ensure we have at least a UID
	if userInfo.UID == "" {
		return nil, fmt.Errorf("no user identifier found in SAML assertion")
	}

	return userInfo, nil
}

// getIdPSSOURL extracts the SSO URL from IdP metadata
func (p *SAMLProvider) getIdPSSOURL() string {
	// This would parse the metadata XML to extract the SSO URL
	// For now, return a placeholder
	return "https://idp.example.com/sso"
}

// getDefaultAttributeMapping returns default SAML attribute mapping
func getDefaultAttributeMapping() map[string]string {
	return map[string]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    "given_name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":      "family_name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department":   "department",
	}
}
