package saml

import (
	"encoding/json"
	"fmt"

	"github.com/crewjam/saml"
	"github.com/thecybersailor/slauth/pkg/types"
)

// AttributeMapper handles mapping of SAML attributes to user info
type AttributeMapper struct {
	mapping map[string]string
}

// NewAttributeMapper creates a new attribute mapper
func NewAttributeMapper(mappingJSON json.RawMessage) (*AttributeMapper, error) {
	var mapping map[string]string

	if len(mappingJSON) > 0 {
		if err := json.Unmarshal(mappingJSON, &mapping); err != nil {
			return nil, fmt.Errorf("failed to parse attribute mapping: %w", err)
		}
	} else {
		mapping = getDefaultAttributeMapping()
	}

	return &AttributeMapper{
		mapping: mapping,
	}, nil
}

// MapAttributes maps SAML assertion attributes to ExternalUserInfo
func (m *AttributeMapper) MapAttributes(assertion *saml.Assertion) (*types.ExternalUserInfo, error) {
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

	// Extract attributes using mapping configuration
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) == 0 {
				continue
			}

			attrValue := attr.Values[0].Value
			mappedField, exists := m.mapping[attr.Name]

			if exists {
				// Map to known user info fields
				switch mappedField {
				case "email":
					userInfo.Email = attrValue
				case "name":
					userInfo.Name = attrValue
				case "avatar":
					userInfo.Avatar = attrValue
				case "locale":
					userInfo.Locale = attrValue
				case "given_name":
					userInfo.Metadata["given_name"] = attrValue
				case "family_name":
					userInfo.Metadata["family_name"] = attrValue
				case "department":
					userInfo.Metadata["department"] = attrValue
				case "title":
					userInfo.Metadata["title"] = attrValue
				case "phone":
					userInfo.Metadata["phone"] = attrValue
				default:
					// Store in metadata with mapped name
					userInfo.Metadata[mappedField] = attrValue
				}
			} else {
				// Store unmapped attributes in metadata with original name
				userInfo.Metadata[attr.Name] = attrValue
			}
		}
	}

	// Validation: ensure we have at least a UID
	if userInfo.UID == "" {
		return nil, fmt.Errorf("no user identifier found in SAML assertion")
	}

	return userInfo, nil
}

// GetMapping returns the current attribute mapping
func (m *AttributeMapper) GetMapping() map[string]string {
	return m.mapping
}

// UpdateMapping updates the attribute mapping
func (m *AttributeMapper) UpdateMapping(newMapping map[string]string) {
	m.mapping = newMapping
}

// ValidateMapping validates the attribute mapping configuration
func (m *AttributeMapper) ValidateMapping() error {
	if m.mapping == nil {
		return fmt.Errorf("attribute mapping cannot be nil")
	}

	// Check for reserved field names
	reservedFields := map[string]bool{
		"uid":    true,
		"email":  true,
		"name":   true,
		"avatar": true,
		"locale": true,
	}

	for samlAttr, mappedField := range m.mapping {
		if samlAttr == "" {
			return fmt.Errorf("SAML attribute name cannot be empty")
		}

		if mappedField == "" {
			return fmt.Errorf("mapped field name cannot be empty for attribute %s", samlAttr)
		}

		// Warn about potential conflicts (but don't fail)
		if reservedFields[mappedField] {
			// This is fine, just mapping to standard fields
			continue
		}
	}

	return nil
}

// GetSupportedFields returns the list of supported mapping target fields
func GetSupportedFields() []string {
	return []string{
		"email",
		"name",
		"avatar",
		"locale",
		"given_name",
		"family_name",
		"department",
		"title",
		"phone",
	}
}

// GetCommonSAMLAttributes returns common SAML attribute names
func GetCommonSAMLAttributes() map[string]string {
	return map[string]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "Email Address",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "Full Name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    "Given Name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":      "Surname",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department":   "Department",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title":        "Job Title",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone":  "Mobile Phone",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality":     "Locality",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country":      "Country",
		"urn:oid:0.9.2342.19200300.100.1.3":                                  "Email (OID)",
		"urn:oid:2.5.4.42":                                                   "Given Name (OID)",
		"urn:oid:2.5.4.4":                                                    "Surname (OID)",
		"urn:oid:2.16.840.1.113730.3.1.241":                                  "Display Name (OID)",
	}
}
