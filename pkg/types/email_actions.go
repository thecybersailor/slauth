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
