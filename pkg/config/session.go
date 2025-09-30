package config

import "time"

type SessionConfig struct {
	// Detect and revoke potentially compromised refresh tokens
	// Prevent replay attacks from potentially compromised refresh tokens.
	RevokeCompromisedRefreshTokens bool

	// Refresh token reuse interval
	// Time interval where the same refresh token can be used multiple times
	// to request for an access token. Recommendation: 10 seconds.
	RefreshTokenReuseInterval time.Duration

	// Enforce single session per user
	// If enabled, all but a user's most recently active session will be terminated.
	EnforceSingleSessionPerUser bool

	// Time-box user sessions
	// The amount of time before a user is forced to sign in again. Use 0 for never.
	TimeBoxUserSessions time.Duration

	// Inactivity timeout
	// The amount of time a user needs to be inactive to be forced to sign in again. Use 0 for never.
	InactivityTimeout time.Duration

	// Access token TTL
	// The time-to-live (TTL) for access tokens. Recommendation: 1 hour.
	AccessTokenTTL time.Duration

	// Refresh token TTL
	// The time-to-live (TTL) for refresh tokens. Recommendation: 1 week.
	RefreshTokenTTL time.Duration
}

// GetDefaultSessionConfig returns the default session configuration
func GetDefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		RevokeCompromisedRefreshTokens: true,
		RefreshTokenReuseInterval:      10 * time.Second,
		EnforceSingleSessionPerUser:    false,
		TimeBoxUserSessions:            0,                           // Never expire
		InactivityTimeout:              0,                           // No inactivity timeout
		AccessTokenTTL:                 3600 * time.Second,          // 1 hour
		RefreshTokenTTL:                7 * 24 * 3600 * time.Second, // 1 week
	}
}
