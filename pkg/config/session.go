package config

type SessionConfig struct {
	// Detect and revoke potentially compromised refresh tokens
	// Prevent replay attacks from potentially compromised refresh tokens.
	RevokeCompromisedRefreshTokens bool `json:"revoke_compromised_refresh_tokens"`

	// Refresh token reuse interval (in seconds)
	// Time interval where the same refresh token can be used multiple times
	// to request for an access token. Recommendation: 10 seconds.
	RefreshTokenReuseInterval int64 `json:"refresh_token_reuse_interval"`

	// Enforce single session per user
	// If enabled, all but a user's most recently active session will be terminated.
	EnforceSingleSessionPerUser bool `json:"enforce_single_session_per_user"`

	// Time-box user sessions (in seconds)
	// The amount of time before a user is forced to sign in again. Use 0 for never.
	TimeBoxUserSessions int64 `json:"time_box_user_sessions"`

	// Inactivity timeout (in seconds)
	// The amount of time a user needs to be inactive to be forced to sign in again. Use 0 for never.
	InactivityTimeout int64 `json:"inactivity_timeout"`

	// Access token TTL (in seconds)
	// The time-to-live (TTL) for access tokens. Recommendation: 1 hour.
	AccessTokenTTL int64 `json:"access_token_ttl"`

	// Refresh token TTL (in seconds)
	// The time-to-live (TTL) for refresh tokens. Recommendation: 1 week.
	RefreshTokenTTL int64 `json:"refresh_token_ttl"`
}

// GetDefaultSessionConfig returns the default session configuration
func GetDefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		RevokeCompromisedRefreshTokens: true,
		RefreshTokenReuseInterval:      10, // 10 seconds
		EnforceSingleSessionPerUser:    false,
		TimeBoxUserSessions:            0,             // Never expire
		InactivityTimeout:              0,             // No inactivity timeout
		AccessTokenTTL:                 3600,          // 1 hour
		RefreshTokenTTL:                7 * 24 * 3600, // 1 week
	}
}
