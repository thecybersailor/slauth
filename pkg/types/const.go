package types

// AALLevel represents authentication assurance level
type AALLevel string

const (
	AALLevel1 AALLevel = "aal1"
	AALLevel2 AALLevel = "aal2"
	AALLevel3 AALLevel = "aal3"
)

// CodeChallengeMethod represents OAuth2 PKCE code challenge method
type CodeChallengeMethod string

const (
	CodeChallengeMethodS256  CodeChallengeMethod = "s256"
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
)

// FactorStatus represents MFA factor verification status
type FactorStatus string

const (
	FactorStatusUnverified FactorStatus = "unverified"
	FactorStatusVerified   FactorStatus = "verified"
)

// FactorType represents MFA factor type
type FactorType string

const (
	FactorTypeTOTP     FactorType = "totp"
	FactorTypeWebAuthn FactorType = "webauthn"
	FactorTypePhone    FactorType = "phone"
)

// OAuthRegistrationType represents OAuth client registration type
type OAuthRegistrationType string

const (
	OAuthRegistrationTypeDynamic OAuthRegistrationType = "dynamic"
	OAuthRegistrationTypeManual  OAuthRegistrationType = "manual"
)

// OneTimeTokenType represents different types of one-time tokens
type OneTimeTokenType string

const (
	OneTimeTokenTypeConfirmation       OneTimeTokenType = "confirmation_token"
	OneTimeTokenTypeReauthentication   OneTimeTokenType = "reauthentication_token"
	OneTimeTokenTypeRecovery           OneTimeTokenType = "recovery_token"
	OneTimeTokenTypeEmailChangeNew     OneTimeTokenType = "email_change_token_new"
	OneTimeTokenTypeEmailChangeCurrent OneTimeTokenType = "email_change_token_current"
	OneTimeTokenTypePhoneChange        OneTimeTokenType = "phone_change_token"
)
