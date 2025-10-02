package controller

import (
	"github.com/thecybersailor/slauth/pkg/config"
)

// Admin request/response types

// QueryUsersRequest represents the request for querying users (Strapi-style)
type QueryUsersRequest struct {
	Filters    map[string]interface{} `json:"filters"`
	Sort       []string               `json:"sort"`
	Pagination *QueryPagination       `json:"pagination"`
}

// QueryPagination represents pagination parameters
type QueryPagination struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
}

// ListUsersResponse represents the response for listing users
type ListUsersResponse struct {
	Users    []*AdminUserResponse `json:"users,omitempty"`
	Total    int64                `json:"total"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
}

// AdminUserResponse represents a user in admin responses
type AdminUserResponse struct {
	ID              string                 `json:"id"`
	Email           *string                `json:"email,omitempty"`
	Phone           *string                `json:"phone,omitempty"`
	EmailConfirmed  bool                   `json:"email_confirmed"`
	PhoneConfirmed  bool                   `json:"phone_confirmed"`
	IsAnonymous     bool                   `json:"is_anonymous"`
	BannedUntil     *string                `json:"banned_until,omitempty"`
	LastSignInAt    *string                `json:"last_sign_in_at,omitempty"`
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       string                 `json:"updated_at"`
	RawUserMetaData map[string]interface{} `json:"user_meta_data,omitempty"`
	RawAppMetaData  map[string]interface{} `json:"app_meta_data,omitempty"`
}

// AdminCreateUserRequest represents the request for creating a user
type AdminCreateUserRequest struct {
	Email          string                 `json:"email"`
	Phone          string                 `json:"phone"`
	Password       string                 `json:"password"`
	UserData       map[string]interface{} `json:"user_data,omitempty"`
	UserMetadata   map[string]interface{} `json:"user_metadata,omitempty"`
	AppMetadata    map[string]interface{} `json:"app_metadata,omitempty"`
	EmailConfirmed bool                   `json:"email_confirmed"`
	PhoneConfirmed bool                   `json:"phone_confirmed"`
}

// AdminUpdateUserRequest represents the request for updating a user
type AdminUpdateUserRequest struct {
	Email          *string                `json:"email,omitempty"`
	Phone          *string                `json:"phone,omitempty"`
	UserData       map[string]interface{} `json:"user_data,omitempty"`
	AppMetadata    map[string]interface{} `json:"app_metadata,omitempty"`
	EmailConfirmed *bool                  `json:"email_confirmed,omitempty"`
	PhoneConfirmed *bool                  `json:"phone_confirmed,omitempty"`
	BannedUntil    *string                `json:"banned_until,omitempty"`
}

// AdminResetPasswordRequest represents the request for resetting user password
type AdminResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// ListSessionsRequest represents the request for listing sessions
type ListSessionsRequest struct {
	Page     int `json:"page" form:"page"`
	PageSize int `json:"page_size" form:"page_size"`
}

// ListSessionsResponse represents the response for listing sessions
type ListSessionsResponse struct {
	Sessions []*SessionResponse `json:"sessions,omitempty"`
	Total    int64              `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
}

// SessionResponse represents a session in admin responses
type SessionResponse struct {
	ID          string  `json:"id"`
	UserID      string  `json:"user_id"`
	AAL         string  `json:"aal"`
	UserAgent   *string `json:"user_agent,omitempty"`
	IP          *string `json:"ip,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	RefreshedAt *string `json:"refreshed_at,omitempty"`
}

// ListIdentitiesResponse represents the response for listing user identities
type ListIdentitiesResponse struct {
	Identities []*IdentityResponse `json:"identities,omitempty"`
}

// IdentityResponse represents an identity in admin responses
type IdentityResponse struct {
	ID           string                 `json:"id"`
	Provider     string                 `json:"provider"`
	ProviderID   string                 `json:"provider_id"`
	IdentityData map[string]interface{} `json:"identity_data,omitempty"`
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
}

// StatsResponse represents system statistics
type StatsResponse struct {
	Count int64 `json:"count"`
}

// RecentSignupsRequest represents the request for recent signups
type RecentSignupsRequest struct {
	Days int `json:"days" form:"days"`
}

// RecentSigninsRequest represents the request for recent signins
type RecentSigninsRequest struct {
	Days int `json:"days" form:"days"`
}

// ===== Statistics Types =====

// SessionStatsResponse represents session statistics
type SessionStatsResponse struct {
	TotalSessions   int64 `json:"total_sessions"`
	ActiveSessions  int64 `json:"active_sessions"`
	ExpiredSessions int64 `json:"expired_sessions"`
}

// ListRecentSigninsRequest represents the request for recent signins
type ListRecentSigninsRequest struct {
	Limit int `json:"limit" form:"limit"`
}

// RecentSigninsResponse represents the response for recent signins
type RecentSigninsResponse struct {
	RecentSignins []*RecentSigninResponse `json:"recent_signins,omitempty"`
}

// RecentSigninResponse represents a recent signin
type RecentSigninResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	SigninAt  string `json:"signin_at"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// UpdateInstanceConfigRequest represents the request for updating instance config
type UpdateInstanceConfigRequest struct {
	Config config.AuthServiceConfig `json:"config"`
}

// GetInstanceConfigResponse represents the response for getting instance config
type GetInstanceConfigResponse struct {
	DomainCode string                   `json:"domain_code"`
	Config     config.AuthServiceConfig `json:"config"`
}

// UpdateInstanceConfigResponse represents the response for updating instance config
type UpdateInstanceConfigResponse struct {
	Message string                   `json:"message"`
	Config  config.AuthServiceConfig `json:"config"`
}
