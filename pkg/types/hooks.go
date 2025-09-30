package types

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

type OnSendEmailHook func(ctx context.Context, email string, template string) error

type OnSendSMSHook func(ctx context.Context, phone string, template string) error

// Customize Access Token (JWT) Claims hook
type OnCustomizeAccessTokenClaimsHook func(ctx context.Context, claims jwt.MapClaims) error

type BeforeUserCreationHook func(ctx context.Context, user *User) error

type MFAValidationAttemptHook func(ctx context.Context, user *User, mfaFactor *MFAFactor) error

type PasswordValidationAttemptHook func(ctx context.Context, user *User, password string) error

type User interface {
}

type MFAFactor interface {
}
