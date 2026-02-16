package types

import (
	"encoding/json"
)

// ===== Request Types =====

// SignUpRequest represents the signup request payload
type SignUpRequest struct {
	Email        string         `json:"email,omitempty"`
	Phone        string         `json:"phone,omitempty"`
	Password     string         `json:"password"`
	UserMetadata map[string]any `json:"user_metadata,omitempty"`
	Options      *SignUpOptions `json:"options,omitempty"`
}

type SignUpOptions struct {
	EmailRedirectTo string         `json:"emailRedirectTo,omitempty"`
	CaptchaToken    string         `json:"captchaToken,omitempty"`
	Channel         string         `json:"channel,omitempty"` // sms, whatsapp
	RedirectTo      string         `json:"redirect_to,omitempty"`
	Data            map[string]any `json:"data,omitempty"` // Additional data like is_anonymous
}

// SignInWithPasswordRequest represents the password login request
type SignInWithPasswordRequest struct {
	Email    string                     `json:"email,omitempty"`
	Phone    string                     `json:"phone,omitempty"`
	Password string                     `json:"password"`
	Options  *SignInWithPasswordOptions `json:"options,omitempty"`
}

type SignInWithPasswordOptions struct {
	CaptchaToken string `json:"captchaToken,omitempty"`
	RedirectTo   string `json:"redirect_to,omitempty"`
}

// SignInWithOtpRequest represents the OTP login request
type SignInWithOtpRequest struct {
	Email   string                `json:"email,omitempty"`
	Phone   string                `json:"phone,omitempty"`
	Options *SignInWithOtpOptions `json:"options,omitempty"`
}

type SignInWithOtpOptions struct {
	EmailRedirectTo  string         `json:"emailRedirectTo,omitempty"`
	ShouldCreateUser bool           `json:"shouldCreateUser"`
	Data             map[string]any `json:"data,omitempty"`
	CaptchaToken     string         `json:"captchaToken,omitempty"`
	Channel          string         `json:"channel,omitempty"` // sms, whatsapp
	RedirectTo       string         `json:"redirect_to,omitempty"`
}

// SendOTPRequest represents the send OTP request
type SendOTPRequest struct {
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
	Channel string `json:"channel,omitempty"` // sms, whatsapp
}

// VerifyOtpRequest represents the OTP verification request
type VerifyOtpRequest struct {
	Email       string            `json:"email,omitempty"`
	Phone       string            `json:"phone,omitempty"`
	Token       string            `json:"token,omitempty"`
	SessionCode string            `json:"session_code,omitempty"`
	TokenHash   string            `json:"token_hash,omitempty"`
	Type        string            `json:"type"` // signup, invite, magiclink, recovery, email_change, sms, phone_change
	Options     *VerifyOtpOptions `json:"options,omitempty"`
}

type VerifyOtpOptions struct {
	RedirectTo   string `json:"redirect_to,omitempty"`
	CaptchaToken string `json:"captchaToken,omitempty"`
}

// ResetPasswordRequest represents password reset request
type ResetPasswordRequest struct {
	Email   string                `json:"email,omitempty"`
	Phone   string                `json:"phone,omitempty"`
	Options *ResetPasswordOptions `json:"options,omitempty"`
}

type ResetPasswordOptions struct {
	RedirectTo   string `json:"redirect_to,omitempty"`
	CaptchaToken string `json:"captchaToken,omitempty"`
}

// UpdatePasswordRequest represents password update request
type UpdatePasswordRequest struct {
	Password string `json:"password"`
	Nonce    string `json:"nonce,omitempty"`
}

// SignInWithOAuthRequest represents OAuth login request
type SignInWithOAuthRequest struct {
	Provider string          `json:"provider"`
	Options  json.RawMessage `json:"options,omitempty"`
}

// SignInWithIdTokenRequest represents ID token login request
type SignInWithIdTokenRequest struct {
	Provider   string          `json:"provider"`
	Credential json.RawMessage `json:"credential"`
}

// RefreshTokenRequest represents refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// SignOutRequest represents logout request
type SignOutRequest struct {
	Scope string `json:"scope,omitempty"` // global, local, others
}
