package types

import (
	"database/sql/driver"
	"fmt"
)

// AALLevel represents authentication assurance level
type AALLevel string

const (
	AALLevel1 AALLevel = "aal1"
	AALLevel2 AALLevel = "aal2"
	AALLevel3 AALLevel = "aal3"
)

// Value implements driver.Valuer interface for database serialization
func (a AALLevel) Value() (driver.Value, error) {
	return string(a), nil
}

// Scan implements sql.Scanner interface for database deserialization
func (a *AALLevel) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*a = AALLevel(v)
		return nil
	case []byte:
		*a = AALLevel(v)
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into AALLevel", value)
	}
}

// CodeChallengeMethod represents OAuth2 PKCE code challenge method
type CodeChallengeMethod string

const (
	CodeChallengeMethodS256  CodeChallengeMethod = "s256"
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
)

// Value implements driver.Valuer interface for database serialization
func (c CodeChallengeMethod) Value() (driver.Value, error) {
	return string(c), nil
}

// Scan implements sql.Scanner interface for database deserialization
func (c *CodeChallengeMethod) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*c = CodeChallengeMethod(v)
		return nil
	case []byte:
		*c = CodeChallengeMethod(v)
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into CodeChallengeMethod", value)
	}
}

// FactorStatus represents MFA factor verification status
type FactorStatus string

const (
	FactorStatusUnverified FactorStatus = "unverified"
	FactorStatusVerified   FactorStatus = "verified"
)

// Value implements driver.Valuer interface for database serialization
func (f FactorStatus) Value() (driver.Value, error) {
	return string(f), nil
}

// Scan implements sql.Scanner interface for database deserialization
func (f *FactorStatus) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*f = FactorStatus(v)
		return nil
	case []byte:
		*f = FactorStatus(v)
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into FactorStatus", value)
	}
}

// FactorType represents MFA factor type
type FactorType string

const (
	FactorTypeTOTP     FactorType = "totp"
	FactorTypeWebAuthn FactorType = "webauthn"
	FactorTypePhone    FactorType = "phone"
)

// Value implements driver.Valuer interface for database serialization
func (f FactorType) Value() (driver.Value, error) {
	return string(f), nil
}

// Scan implements sql.Scanner interface for database deserialization
func (f *FactorType) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*f = FactorType(v)
		return nil
	case []byte:
		*f = FactorType(v)
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into FactorType", value)
	}
}

// OAuthRegistrationType represents OAuth client registration type
type OAuthRegistrationType string

const (
	OAuthRegistrationTypeDynamic OAuthRegistrationType = "dynamic"
	OAuthRegistrationTypeManual  OAuthRegistrationType = "manual"
)

// Value implements driver.Valuer interface for database serialization
func (o OAuthRegistrationType) Value() (driver.Value, error) {
	return string(o), nil
}

// Scan implements sql.Scanner interface for database deserialization
func (o *OAuthRegistrationType) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*o = OAuthRegistrationType(v)
		return nil
	case []byte:
		*o = OAuthRegistrationType(v)
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into OAuthRegistrationType", value)
	}
}

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

// Value implements driver.Valuer interface for database serialization
func (o OneTimeTokenType) Value() (driver.Value, error) {
	return string(o), nil
}

// Scan implements sql.Scanner interface for database deserialization
func (o *OneTimeTokenType) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*o = OneTimeTokenType(v)
		return nil
	case []byte:
		*o = OneTimeTokenType(v)
		return nil
	default:
		return fmt.Errorf("cannot scan type %T into OneTimeTokenType", value)
	}
}
