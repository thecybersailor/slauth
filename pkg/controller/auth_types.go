package controller

import (
	"encoding/json"

	"github.com/thecybersailor/slauth/pkg/types"
)

// ===== Request Types =====

type SignUpRequest = types.SignUpRequest
type SignUpOptions = types.SignUpOptions

type SignInWithPasswordRequest = types.SignInWithPasswordRequest
type SignInWithPasswordOptions = types.SignInWithPasswordOptions

type SignInWithOtpRequest = types.SignInWithOtpRequest
type SignInWithOtpOptions = types.SignInWithOtpOptions
type SendOTPRequest = types.SendOTPRequest
type VerifyOtpRequest = types.VerifyOtpRequest
type VerifyOtpOptions = types.VerifyOtpOptions
type SuccessResponse = types.SuccessResponse
type GetAuditLogResponse = types.GetAuditLogResponse
type GetDevicesResponse = types.GetDevicesResponse

// SignInWithOAuthRequest represents OAuth login request
// @Description OAuth authentication request
type SignInWithOAuthRequest struct {
	Provider   string          `json:"provider" example:"google"`
	Options    json.RawMessage `json:"options,omitempty" swaggertype:"object,string"`
	RedirectTo string          `json:"redirect_to,omitempty"`
}

// SignInWithIdTokenRequest represents ID token login request
type SignInWithIdTokenRequest struct {
	Provider   string          `json:"provider" example:"google"`
	Credential json.RawMessage `json:"credential" swaggertype:"object,string"`
}

type SignInWithIdTokenOptions struct {
	CaptchaToken string `json:"captchaToken,omitempty"`
}

// SignInWithSSORequest represents SSO login request
type SignInWithSSORequest struct {
	ProviderId string                `json:"providerId,omitempty"`
	Domain     string                `json:"domain,omitempty"`
	Options    *SignInWithSSOOptions `json:"options,omitempty"`
}

type SignInWithSSOOptions struct {
	RedirectTo   string `json:"redirectTo,omitempty"`
	CaptchaToken string `json:"captchaToken,omitempty"`
}

// RefreshTokenRequest represents refresh token request
// @Description Refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." description:"Refresh token to exchange for new access token"`
}

// ExchangeCodeRequest represents OAuth code exchange request
// @Description OAuth authorization code exchange request (PKCE flow)
type ExchangeCodeRequest struct {
	AuthCode     string `json:"auth_code" example:"abc123def456" description:"Authorization code from OAuth provider"`
	CodeVerifier string `json:"code_verifier" example:"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" description:"PKCE code verifier"`
	State        string `json:"state,omitempty" example:"random_state_string" description:"OAuth state parameter"`
	FlowID       string `json:"flow_id,omitempty" example:"flow_123" description:"Flow identifier"`
}

// SignOutRequest represents logout request
type SignOutRequest struct {
	Scope string `json:"scope,omitempty"` // global, local, others
}

// ResetPasswordRequest represents password reset request
type ResetPasswordRequest = types.ResetPasswordRequest
type ResetPasswordOptions = types.ResetPasswordOptions

// UpdatePasswordRequest represents password update request
type UpdatePasswordRequest struct {
	Password string `json:"password"`
	Nonce    string `json:"nonce,omitempty"`
}

// UpdateUserProfileRequest represents user profile update request
type UpdateUserProfileRequest struct {
	Email           string         `json:"email,omitempty"`
	Phone           string         `json:"phone,omitempty"`
	Password        string         `json:"password,omitempty"`
	UserMetadata    map[string]any `json:"user_metadata,omitempty"`
	EmailRedirectTo string         `json:"emailRedirectTo,omitempty"`
}

// ===== Response Types =====

// AuthData represents authentication response data
// @Description Authentication response containing user and session information
type AuthData struct {
	User         *User         `json:"user,omitempty" description:"User information"`
	Session      *Session      `json:"session,omitempty" description:"Session information with tokens"`
	WeakPassword *WeakPassword `json:"weakPassword,omitempty" description:"Weak password warning (if applicable)"`
	RedirectTo   string        `json:"redirect_to,omitempty" description:"Validated redirect URL"`
}

// User represents user information
// @Description User account information
type User struct {
	ID               string         `json:"id" example:"user_123" description:"Unique user identifier"`
	Aud              string         `json:"aud" example:"authenticated" description:"Audience claim"`
	Email            string         `json:"email,omitempty" example:"user@example.com" description:"User email address"`
	Phone            string         `json:"phone,omitempty" example:"+1234567890" description:"User phone number"`
	CreatedAt        string         `json:"created_at" example:"2023-01-01T00:00:00Z" description:"Account creation timestamp"`
	ConfirmedAt      string         `json:"confirmed_at,omitempty" example:"2023-01-01T00:00:00Z" description:"Account confirmation timestamp"`
	EmailConfirmedAt string         `json:"email_confirmed_at,omitempty" example:"2023-01-01T00:00:00Z" description:"Email confirmation timestamp"`
	PhoneConfirmedAt string         `json:"phone_confirmed_at,omitempty" example:"2023-01-01T00:00:00Z" description:"Phone confirmation timestamp"`
	LastSignInAt     string         `json:"last_sign_in_at,omitempty" example:"2023-01-01T00:00:00Z" description:"Last sign-in timestamp"`
	Role             string         `json:"role,omitempty" example:"user" description:"User role"`
	UpdatedAt        string         `json:"updated_at,omitempty" example:"2023-01-01T00:00:00Z" description:"Last update timestamp"`
	UserMetadata     map[string]any `json:"user_metadata" description:"User-defined metadata"`
	AppMetadata      map[string]any `json:"app_metadata" description:"Application-defined metadata"`
	Identities       []UserIdentity `json:"identities,omitempty" description:"Linked external identities"`
	IsAnonymous      bool           `json:"is_anonymous,omitempty" description:"Whether user is anonymous"`
	Factors          []Factor       `json:"factors,omitempty" description:"MFA factors"`
	AAL              any            `json:"aal,omitempty" description:"Authenticator Assurance Level"`
}

// Session represents authentication session
// @Description Authentication session with tokens
type Session struct {
	ID                   string `json:"id" example:"session_123" description:"Session identifier"`
	AccessToken          string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." description:"JWT access token"`
	RefreshToken         string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." description:"Refresh token"`
	ExpiresIn            int    `json:"expires_in" example:"3600" description:"Token expiration time in seconds"`
	ExpiresAt            int64  `json:"expires_at,omitempty" example:"1672531200" description:"Token expiration timestamp"`
	TokenType            string `json:"token_type" example:"Bearer" description:"Token type"`
	ProviderToken        string `json:"provider_token,omitempty" description:"OAuth provider access token"`
	ProviderRefreshToken string `json:"provider_refresh_token,omitempty" description:"OAuth provider refresh token"`
	User                 *User  `json:"user,omitempty" description:"User information"`
}

type UserIdentity struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	IdentityData map[string]any `json:"identity_data,omitempty"`
	IdentityID   string         `json:"identity_id"`
	Provider     string         `json:"provider"`
	CreatedAt    string         `json:"created_at,omitempty"`
	LastSignInAt string         `json:"last_sign_in_at,omitempty"`
	UpdatedAt    string         `json:"updated_at,omitempty"`
}

type Factor struct {
	ID           string             `json:"id"`
	FriendlyName string             `json:"friendly_name,omitempty"`
	FactorType   types.FactorType   `json:"type"`
	Status       types.FactorStatus `json:"status"`
	CreatedAt    string             `json:"created_at"`
	UpdatedAt    string             `json:"updated_at"`
}

type WeakPassword struct {
	Reasons []string `json:"reasons"`
	Message string   `json:"message"`
}

type AuthError struct {
	Message string `json:"message"`
	Status  int    `json:"status,omitempty"`
	Code    string `json:"code,omitempty"`
}

// OAuthData represents OAuth data (either redirect URL or config for frontend implementation)
type OAuthData struct {
	Provider string `json:"provider"`
	Config   any    `json:"config"`
	FlowID   string `json:"flow_id,omitempty"`
}

// SSOData represents SSO redirect data
type SSOData struct {
	URL string `json:"url"`
}

// UserResponse represents user info response
type UserResponse struct {
	User *User `json:"user,omitempty"`
}

// SendOTPResponse represents send OTP response
type SendOTPResponse struct {
	MessageID string `json:"messageId"`
}

// VerifyOTPRequest represents the verify OTP request
type VerifyOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// SendSMSOTPRequest represents the send SMS OTP request
type SendSMSOTPRequest struct {
	Phone   string `json:"phone"`
	Channel string `json:"channel,omitempty"` // sms, whatsapp
}

// SendSMSOTPResponse represents send SMS OTP response
type SendSMSOTPResponse struct {
	MessageID string `json:"messageId"`
}

// UpdatePasswordResponse represents password update response
type UpdatePasswordResponse struct {
	User *User `json:"user,omitempty"`
}
