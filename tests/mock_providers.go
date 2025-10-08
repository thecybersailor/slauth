package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
)

type MockEmailProvider struct {
	SentEmails []MockEmail
}

type MockEmail struct {
	To      string
	Subject string
	Body    string
}

func NewMockEmailProvider() *MockEmailProvider {
	return &MockEmailProvider{
		SentEmails: make([]MockEmail, 0),
	}
}

func (m *MockEmailProvider) SendEmail(ctx context.Context, to, subject, body string) (messageID *string, err error) {
	slog.Info("Mock: Sending email", "to", to, "subject", subject)
	messageIDStr := "mock-email-" + to
	m.SentEmails = append(m.SentEmails, MockEmail{
		To:      to,
		Subject: subject,
		Body:    body,
	})
	return &messageIDStr, nil
}

func (m *MockEmailProvider) GetLastEmail() *MockEmail {
	if len(m.SentEmails) == 0 {
		return nil
	}
	return &m.SentEmails[len(m.SentEmails)-1]
}

func (m *MockEmailProvider) Clear() {
	m.SentEmails = make([]MockEmail, 0)
}

type MockSMSProvider struct {
	SentSMS []MockSMS
}

type MockSMS struct {
	To   string
	Body string
}

func NewMockSMSProvider() *MockSMSProvider {
	return &MockSMSProvider{
		SentSMS: make([]MockSMS, 0),
	}
}

func (m *MockSMSProvider) SendSMS(ctx context.Context, to, body string) (messageID *string, err error) {
	slog.Info("Mock: Sending SMS", "to", to, "body", body)
	messageIDStr := "mock-sms-" + to
	m.SentSMS = append(m.SentSMS, MockSMS{
		To:   to,
		Body: body,
	})
	return &messageIDStr, nil
}

func (m *MockSMSProvider) GetLastSMS() *MockSMS {
	if len(m.SentSMS) == 0 {
		return nil
	}
	return &m.SentSMS[len(m.SentSMS)-1]
}

func (m *MockSMSProvider) Clear() {
	m.SentSMS = make([]MockSMS, 0)
}

type MockOAuthProvider struct {
	Name     string
	FlowType string // "id_token", "auth_code", "hybrid"
}

type MockOAuthCredential struct {
	Credential string `json:"credential"`
	ClientID   string `json:"client_id"`
}

func NewMockOAuthProvider(name string) *MockOAuthProvider {
	return &MockOAuthProvider{
		Name:     name,
		FlowType: "id_token",
	}
}

func NewMockOAuthProviderWithFlow(name, flowType string) *MockOAuthProvider {
	return &MockOAuthProvider{
		Name:     name,
		FlowType: flowType,
	}
}

func (m *MockOAuthProvider) GetName() string {
	return m.Name
}

func (m *MockOAuthProvider) Authorize(options json.RawMessage) (*types.OAuthConfig, error) {

	var flowType types.FlowType
	switch m.FlowType {
	case "id_token":
		flowType = types.FlowTypeIDToken
	case "auth_code":
		flowType = types.FlowTypeAuthCode
	case "hybrid":
		flowType = types.FlowTypeHybrid
	default:
		flowType = types.FlowTypeIDToken
	}

	return &types.OAuthConfig{
		Config: map[string]any{
			"client_id": "mock-client-id",
		},
		FlowType: flowType,
	}, nil
}

func (m *MockOAuthProvider) ValidateCredential(ctx context.Context, credential json.RawMessage) (*types.OAuthResponse, error) {
	slog.Info("MockOAuthProvider ValidateCredential", "provider", m.Name, "raw_credential", string(credential))

	var credData MockOAuthCredential
	if err := json.Unmarshal(credential, &credData); err != nil {
		slog.Error("MockOAuthProvider ValidateCredential - Unmarshal error", "error", err)
		return nil, fmt.Errorf("invalid credential format: %w", err)
	}

	slog.Info("MockOAuthProvider ValidateCredential - Parsed credential", "credential", credData)

	if credData.Credential == "" {
		return nil, fmt.Errorf("missing credential field")
	}

	if credData.ClientID == "" {
		return nil, fmt.Errorf("missing client_id field")
	}

	userInfo := &types.ExternalUserInfo{
		UID:    "mock-user-123",
		Email:  "mock-user@example.com",
		Name:   "Mock User",
		Avatar: "https://example.com/avatar.jpg",
		Locale: "en",
		Metadata: map[string]any{
			"provider": m.Name,
		},
	}

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken: credData.Credential,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

func (m *MockOAuthProvider) ExchangeCodeForToken(ctx context.Context, code string, redirectURI string) (*types.OAuthResponse, error) {
	slog.Info("MockOAuthProvider ExchangeCodeForToken", "provider", m.Name, "code", code, "redirectURI", redirectURI)

	userInfo := &types.ExternalUserInfo{
		UID:    "mock-user-123",
		Email:  "mock-user@example.com",
		Name:   "Mock User",
		Avatar: "https://example.com/avatar.jpg",
		Locale: "en",
		Metadata: map[string]any{
			"provider": m.Name,
		},
	}

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken: "mock-access-token-" + code,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

type MockSAMLProvider struct {
	Name     string
	EntityID string
	Instance string
}

func NewMockSAMLProvider(name, entityID, instance string) *MockSAMLProvider {
	return &MockSAMLProvider{
		Name:     name,
		EntityID: entityID,
		Instance: instance,
	}
}

func (m *MockSAMLProvider) GetName() string {
	return "saml"
}

func (m *MockSAMLProvider) Authorize(options json.RawMessage) (*types.OAuthConfig, error) {
	return &types.OAuthConfig{
		Config: map[string]any{
			"sso_url":     "https://mock-idp.example.com/sso",
			"relay_state": "mock-relay-state",
			"entity_id":   m.EntityID,
		},
		FlowType: types.FlowTypeAuthCode,
	}, nil
}

func (m *MockSAMLProvider) ValidateCredential(ctx context.Context, credential json.RawMessage) (*types.OAuthResponse, error) {
	return nil, fmt.Errorf("SAML authentication should use ExchangeCodeForToken method")
}

func (m *MockSAMLProvider) ExchangeCodeForToken(ctx context.Context, samlResponse string, redirectURI string) (*types.OAuthResponse, error) {
	slog.Info("MockSAMLProvider ExchangeCodeForToken", "provider", m.Name, "samlResponse", samlResponse, "redirectURI", redirectURI)

	userInfo := &types.ExternalUserInfo{
		UID:    "saml-user-123",
		Email:  "saml-user@" + m.Instance,
		Name:   "SAML Test User",
		Locale: "en",
		Metadata: map[string]any{
			"provider":  "saml",
			"entity_id": m.EntityID,
			"instance":  m.Instance,
		},
	}

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken: samlResponse,
		TokenType:   "SAML",
		ExpiresIn:   3600,
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

type MockSAMLServer struct {
	EntityID    string
	SSOURL      string
	Certificate string
	PrivateKey  string
	Users       map[string]*MockSAMLUser
}

type MockSAMLUser struct {
	NameID     string
	Email      string
	Name       string
	Attributes map[string]string
}

func NewMockSAMLServer(entityID, ssoURL string) *MockSAMLServer {
	return &MockSAMLServer{
		EntityID: entityID,
		SSOURL:   ssoURL,
		Users:    make(map[string]*MockSAMLUser),

		Certificate: `-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgIUHD7ft7ThgRABywS25IEHMEa8YjAwDQYJKoZIhvcNAQEL
BQAwQTEWMBQGA1UEAwwNbW9jay1zYW1sLWlkcDEaMBgGA1UECgwRVGVzdCBPcmdh
bml6YXRpb24xCzAJBgNVBAYTAlVTMB4XDTI1MDkyNzEyMTQ0N1oXDTI2MDkyNzEy
MTQ0N1owQTEWMBQGA1UEAwwNbW9jay1zYW1sLWlkcDEaMBgGA1UECgwRVGVzdCBP
cmdhbml6YXRpb24xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA8+FJUG5ncjw2zpC+r2K/bnip52ToCxkJS2tH2U63d9CgWk4uC4JU
YRYeLyRoxECZXzm71isRvL5A2Zxw+BjaRwMJVu54sJzlznfe0MpMXxaujVtKQFRl
y6mY/obVgc92lI58f8Hp+Z12s8qqEwXKF21uFxtGOXVjIneuZQNO4BIf8QDQz0bc
fwvNuqAcD0cF9vYi94HJdZJBzvmdvQaha4RUNYUyPRa7w7w5YKTorPUT4kCvG11y
U1saJtGT8tdCmXRPOxmYM27MThOSS1An6cMNXLd1iRyKsocizy5DMZT2+6E30aY3
PIDyBtaoS9GK0f6Vuw2ETbEwhqHf9549MQIDAQABo1MwUTAdBgNVHQ4EFgQU2I4k
KBwyMTu/twpKAC21A9UUcnYwHwYDVR0jBBgwFoAU2I4kKBwyMTu/twpKAC21A9UU
cnYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAXxirXTBKYb1s
8mFluWf1E6XA5fLKNEEOHBIbSy6FWC8AMWY3PRykHFAZ5yrQTCgTct3rkHfNWz5+
Uy623Zt+FpKChQpTreQkikN8aMgm7zWeterdViizMYjJnHYbURBJcnQOt72BP1zi
UC/Wv/+8bNKc+HIZBESMVP+D9+tVt2UnyJGZ+kEfnDDeOvYR1/10+J+QYqwgTSk6
kqZW3ZWN1VfXkYSShBDal2gw0I2dmLaduAMIZ//3AQJw5qbBYCuITFY2w8TFMUv2
XvQl1vtGl4UQ7FAck/Fm3BhTPIuOmPnA6lupf5DHNPuX+iB+4XsVg2w1roeJSbfJ
TpEyovPmtQ==
-----END CERTIFICATE-----`,

		PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA8+FJUG5ncjw2zpC+r2K/bnip52ToCxkJS2tH2U63d9CgWk4u
C4JUYRYeLyRoxECZXzm71isRvL5A2Zxw+BjaRwMJVu54sJzlznfe0MpMXxaujVtK
QFRly6mY/obVgc92lI58f8Hp+Z12s8qqEwXKF21uFxtGOXVjIneuZQNO4BIf8QDQ
z0bcfwvNuqAcD0cF9vYi94HJdZJBzvmdvQaha4RUNYUyPRa7w7w5YKTorPUT4kCv
G11yU1saJtGT8tdCmXRPOxmYM27MThOSS1An6cMNXLd1iRyKsocizy5DMZT2+6E3
0aY3PIDyBtaoS9GK0f6Vuw2ETbEwhqHf9549MQIDAQABAoIBAQDvSbn0mA8Z7+ja
rvzZ+yrXSr9yUfi3gt4yyNVba7fqcKIVWSYmlr8R73C4UqIVBUk3PN+HmQSzS303
xx603zW0fU85o4x5xchZ2BWgiQ18MzYbblohWm3y8boy6rssvhGcW13ewLZA+/ZP
HGfZeFG8wNtHArTZhcs6M3HCnQdUI6oms3P8UzXyv+2X71L4p97z+zzEMyzHwHH+
Kc1HHO6LqKptSzJnb3T05XkYOkxz1TBHmtWcNEIPzhdz71wnUfyDbh+907av4t/9
EUSS/rYsE+iPgvonGITCRISd961KqykfE2qw8oxReWtpgG9ktJnPxmcncXMEIz1F
XF3uF4xdAoGBAPxUsfmCtwkb6dzkucloiWBbVQNli26lkTqAovZCcjpOlqONhhe9
3tlwAfBve44s9KuoakebrPYqxN3basN6xPpdqKyKHXRASoWDNoUPvWM8iytnj8ZC
1ZfcAZ3WObENIcIpQ5/nmqGK2IbvEApj1Z14xT0zd9a1UjKaEHWTUl5/AoGBAPdt
IgW/gDj2Zl0LNi1bIaOaHaSPDWXRE/nRxebZ5EENA9U4I7s2qZB3GDJEPyG2W5Et
R89+iQ7/xHrERCJYv0WWo4ljKNjCZO1M5A9YfL5uWP3IwlFjAKFNBPn4/XGedWWU
+mNVbpAl7KrsSU53OdgMQWt9DViA8u0GlA3O6uxPAoGBALvDTlgrc4Yctk5ACRud
ZTRFYiJP6oxgOYw98oWq9hL7Lc7wXcrG59AHL/o5CsjGHR6rCMLWTcM0GiA4yN5D
OdZP4Vbaw4Yg3RMyi1xCVRxGDg0zV+IhE42YEb/gjDd6XRd82yxfDEqO5gaqV9ZT
ab5vAt5CsTcc39h1mi/Te2SDAoGAYIVkRlXEUXRdzmI3Sk5Iuye99JoRoeyEHGqn
Bz1s+6t2GVGDLt9OGps7BzD0Z9RZuDKv1tQH56ADJ9k0sylnxF/VgBz8rEJ5WNEs
Doh4cVlewfH1TAaREluXW2S0igREy9HoM6P6M6V3w93VYxTDrfJp+uKXuDTlj22H
iDN2FaUCgYAqbsAFUB6e9oyYH1+4q7ji5Fngp89IStMjL8aybePnXvWsurpj8CZ+
G98XzBWA2WrYIdpuafpUIy12ofcA5DCwJ5Th0AUd4v7zoizj0FEfV/AIfLi5PMhU
Js1fROhIsQomWOBYlfbZS2gqKvGHU4VvpBhs3j0ezeO7X6MkBLnbNw==
-----END RSA PRIVATE KEY-----`,
	}
}

func (s *MockSAMLServer) AddUser(nameID, email, name string, attributes map[string]string) {
	s.Users[nameID] = &MockSAMLUser{
		NameID:     nameID,
		Email:      email,
		Name:       name,
		Attributes: attributes,
	}
}

func (s *MockSAMLServer) GenerateMetadata() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, s.EntityID, s.getCertificateData(), s.SSOURL)
}

func (s *MockSAMLServer) getCertificateData() string {

	cert := s.Certificate
	cert = strings.ReplaceAll(cert, "-----BEGIN CERTIFICATE-----", "")
	cert = strings.ReplaceAll(cert, "-----END CERTIFICATE-----", "")
	cert = strings.ReplaceAll(cert, "\n", "")
	return strings.TrimSpace(cert)
}

func (s *MockSAMLServer) GenerateSAMLResponse(nameID, relayState string) string {
	user, exists := s.Users[nameID]
	if !exists {
		return ""
	}

	attributeStatements := ""
	for attrName, attrValue := range user.Attributes {
		attributeStatements += fmt.Sprintf(`
      <saml:Attribute Name="%s">
        <saml:AttributeValue>%s</saml:AttributeValue>
      </saml:Attribute>`, attrName, attrValue)
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_%s" 
                Version="2.0" 
                IssueInstant="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
                  ID="_%s" 
                  Version="2.0" 
                  IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>%s
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		generateRandomID(),
		time.Now().Format(time.RFC3339),
		s.EntityID,
		generateRandomID(),
		time.Now().Format(time.RFC3339),
		s.EntityID,
		user.Email,
		attributeStatements)
}

func generateRandomID() string {
	return fmt.Sprintf("id%d", time.Now().UnixNano())
}

var _ types.EmailProvider = (*MockEmailProvider)(nil)
var _ types.SMSProvider = (*MockSMSProvider)(nil)
var _ types.IdentityProvider = (*MockOAuthProvider)(nil)
var _ types.IdentityProvider = (*MockSAMLProvider)(nil)
