package services

import (
	"context"
	"encoding/json"
)

// WebAuthnRPConfig configures the relying party (RP).
//
// This is intentionally separated from AuthServiceConfig to keep the surface
// minimal and allow callers to derive it from their own config sources.
type WebAuthnRPConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

// WebAuthnUser identifies a user for WebAuthn ceremonies.
type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
}

// WebAuthnEngine abstracts WebAuthn ceremonies for testability.
//
// JSON payloads are used at the boundary to avoid coupling controllers/services
// to a specific WebAuthn library's public types.
type WebAuthnEngine interface {
	BeginRegistration(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, excludeCredentialIDs [][]byte) (creationOptions json.RawMessage, sessionData json.RawMessage, err error)
	FinishRegistration(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, sessionData json.RawMessage, attestationResponse json.RawMessage) (storedCredential json.RawMessage, err error)

	BeginLogin(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, allowCredentialIDs [][]byte) (requestOptions json.RawMessage, sessionData json.RawMessage, err error)
	FinishLogin(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, sessionData json.RawMessage, assertionResponse json.RawMessage, storedCredentials []json.RawMessage) (updatedStoredCredential json.RawMessage, err error)
}
