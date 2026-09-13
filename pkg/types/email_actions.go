package types

import "time"

type EmailActionPurpose string

const (
	EmailActionPurposeSignup           EmailActionPurpose = "signup"
	EmailActionPurposeReauthentication EmailActionPurpose = "reauthentication"
	EmailActionPurposeRecovery         EmailActionPurpose = "recovery"
	EmailActionPurposeEmailChange      EmailActionPurpose = "email_change"
)

type EmailActionSecretKind string

const (
	EmailActionSecretKindCode EmailActionSecretKind = "code"
	EmailActionSecretKindLink EmailActionSecretKind = "link"
)

type EmailActionIssueRequest struct {
	InstanceID          string
	Purpose             EmailActionPurpose
	SecretKind          EmailActionSecretKind
	UserID              *uint
	SessionID           *uint
	Email               string
	OriginalEmail       string
	PendingPasswordHash *string
	CredentialDigest    string
	TTL                 time.Duration
}

type EmailActionIssueResult struct {
	ID        string    `json:"challenge_id"`
	Secret    string    `json:"-"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type EmailSignupStartRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type EmailSignupResendRequest struct {
	ChallengeID string `json:"challenge_id"`
}

type EmailSignupVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

type EmailSignupChallengeResponse struct {
	Message     string `json:"message"`
	ChallengeID string `json:"challenge_id"`
	ExpiresIn   int64  `json:"expires_in"`
}

type EmailActionSuccessResponse struct {
	Success bool `json:"success"`
}
