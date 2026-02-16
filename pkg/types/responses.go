package types

// ===== Response Types =====

type AuthData struct {
	User         *UserData     `json:"user"`
	Session      *Session      `json:"session"`
	WeakPassword *WeakPassword `json:"weakPassword,omitempty"`
}

type UserData struct {
	ID               string         `json:"id"`
	Aud              string         `json:"aud"`
	Email            string         `json:"email,omitempty"`
	Phone            string         `json:"phone,omitempty"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
	EmailConfirmedAt *string        `json:"email_confirmed_at,omitempty"`
	PhoneConfirmedAt *string        `json:"phone_confirmed_at,omitempty"`
	LastSignInAt     *string        `json:"last_sign_in_at,omitempty"`
	Role             string         `json:"role,omitempty"`
	UserMetadata     map[string]any `json:"user_metadata,omitempty"`
	AppMetadata      map[string]any `json:"app_metadata,omitempty"`
	Identities       []Identity     `json:"identities,omitempty"`
	Factors          []FactorData   `json:"factors,omitempty"`
}

type Session struct {
	AccessToken     string    `json:"access_token"`
	TokenType       string    `json:"token_type"`
	ExpiresIn       int       `json:"expires_in"`
	ExpiresAt       int64     `json:"expires_at"`
	RefreshToken    string    `json:"refresh_token"`
	User            *UserData `json:"user"`
	ProviderToken   string    `json:"provider_token,omitempty"`
	ProviderRefresh string    `json:"provider_refresh_token,omitempty"`
}

type Identity struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	Provider     string         `json:"provider"`
	ProviderID   string         `json:"provider_id"`
	IdentityData map[string]any `json:"identity_data"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
}

type FactorData struct {
	ID           string       `json:"id"`
	FriendlyName string       `json:"friendly_name,omitempty"`
	FactorType   FactorType   `json:"factor_type"`
	Status       FactorStatus `json:"status"`
	CreatedAt    string       `json:"created_at"`
	UpdatedAt    string       `json:"updated_at"`
}

type WeakPassword struct {
	Reasons []string `json:"reasons"`
	Message string   `json:"message"`
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
	User *UserData `json:"user"`
}

// SendOTPResponse represents send OTP response
type SendOTPResponse struct {
	MessageID   string `json:"messageId"`
	SessionCode string `json:"session_code"`
}

// VerifyOTPResponse represents verify OTP response
type VerifyOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SuccessResponse represents simple success response
type SuccessResponse struct {
	Success bool `json:"success"`
}

// SendSMSOTPResponse represents send SMS OTP response
type SendSMSOTPResponse struct {
	MessageID   string `json:"messageId"`
	SessionCode string `json:"session_code"`
}

type APIError struct {
	Message string `json:"message"`
	Status  int    `json:"status,omitempty"`
	Code    string `json:"code,omitempty"`
}

// GetAuditLogResponse represents audit log response
type GetAuditLogResponse struct {
	Events []map[string]interface{} `json:"events"`
}

// GetDevicesResponse represents devices response
type GetDevicesResponse struct {
	Devices []map[string]interface{} `json:"devices"`
}
