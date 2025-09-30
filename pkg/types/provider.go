package types

import (
	"context"
	"encoding/json"
)

type CaptchaProvider interface {
	ValidateCaptcha(ctx context.Context, captchaToken string) (bool, error)
}

type MFAProvider interface {
	GetName() string
	Enroll(ctx context.Context, factorType FactorType, issuer string, friendlyName string, phone string) (string, error)
	Challenge(ctx context.Context, factorID string, channel string) (string, error)
	Verify(ctx context.Context, factorID string, challengeID string, code string) (string, error)
	Unenroll(ctx context.Context, factorID string) error
	ListFactors(ctx context.Context) ([]Factor, error)
}

type Factor interface {
	ID() string
	Type() FactorType
	Status() FactorStatus
}

type IdentityProvider interface {
	GetName() string

	Authorize(options json.RawMessage) (*OAuthConfig, error)

	ValidateCredential(ctx context.Context, credential json.RawMessage) (*OAuthResponse, error)

	ExchangeCodeForToken(ctx context.Context, code string, redirectURI string) (*OAuthResponse, error)
}

type OAuthConfig struct {
	Config   any      `json:"config"`
	FlowType FlowType `json:"flow_type"`
}

type FlowType string

const (
	FlowTypeIDToken  FlowType = "id_token"
	FlowTypeAuthCode FlowType = "auth_code"
	FlowTypeHybrid   FlowType = "hybrid"
)

type OAuthTokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type OAuthResponse struct {
	UserInfo  *ExternalUserInfo `json:"user_info"`
	TokenInfo *OAuthTokenInfo   `json:"token_info"`
}

type ExternalUserInfo struct {
	UID      string         `json:"uid"`
	Email    string         `json:"email,omitempty"`
	Phone    string         `json:"phone,omitempty"`
	Username string         `json:"username,omitempty"`
	Name     string         `json:"name"`
	Avatar   string         `json:"avatar,omitempty"`
	Locale   string         `json:"locale,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *AuthError) Error() string {
	return e.Message
}

type SMSProvider interface {
	SendSMS(ctx context.Context, phone string, message string) (messageID *string, err error)
}

type EmailProvider interface {
	SendEmail(ctx context.Context, to string, subject string, body string) (messageID *string, err error)
}
