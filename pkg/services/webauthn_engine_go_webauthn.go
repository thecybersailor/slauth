package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	go_webauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/thecybersailor/slauth/pkg/consts"
)

// GoWebAuthnEngine is the default WebAuthnEngine implementation.
//
// NOTE: The full implementation is added in follow-up tasks; this constructor
// and type exist to enable wiring + TDD.
type GoWebAuthnEngine struct{}

func NewGoWebAuthnEngine(rp WebAuthnRPConfig) (*GoWebAuthnEngine, error) {
	if rp.RPID == "" || rp.RPDisplayName == "" || len(rp.RPOrigins) == 0 {
		return nil, consts.VALIDATION_FAILED
	}
	return &GoWebAuthnEngine{}, nil
}

func (e *GoWebAuthnEngine) BeginRegistration(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, excludeCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	w, err := go_webauthn.New(&go_webauthn.Config{
		RPID:          rp.RPID,
		RPDisplayName: rp.RPDisplayName,
		RPOrigins:     rp.RPOrigins,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("init webauthn: %w", err)
	}

	waUser := &goWebAuthnUser{
		id:          user.ID,
		name:        user.Name,
		displayName: user.DisplayName,
	}

	var opts []go_webauthn.RegistrationOption
	if len(excludeCredentialIDs) > 0 {
		exclude := make([]protocol.CredentialDescriptor, 0, len(excludeCredentialIDs))
		for _, id := range excludeCredentialIDs {
			exclude = append(exclude, protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: id,
			})
		}
		opts = append(opts, go_webauthn.WithExclusions(exclude))
	}

	creation, session, err := w.BeginRegistration(waUser, opts...)
	if err != nil {
		return nil, nil, err
	}

	optionsBytes, err := json.Marshal(map[string]any{"publicKey": creation.Response})
	if err != nil {
		return nil, nil, err
	}
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return json.RawMessage(optionsBytes), json.RawMessage(sessionBytes), nil
}

func (e *GoWebAuthnEngine) FinishRegistration(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, sessionData json.RawMessage, attestationResponse json.RawMessage) (json.RawMessage, error) {
	w, err := go_webauthn.New(&go_webauthn.Config{
		RPID:          rp.RPID,
		RPDisplayName: rp.RPDisplayName,
		RPOrigins:     rp.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	var session go_webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return nil, consts.VALIDATION_FAILED
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(attestationResponse)
	if err != nil {
		return nil, consts.VALIDATION_FAILED
	}

	waUser := &goWebAuthnUser{
		id:          user.ID,
		name:        user.Name,
		displayName: user.DisplayName,
	}

	cred, err := w.CreateCredential(waUser, session, parsed)
	if err != nil {
		return nil, consts.VALIDATION_FAILED
	}

	return marshalStoredWebAuthnCredential(cred)
}

func (e *GoWebAuthnEngine) BeginLogin(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, allowCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	w, err := go_webauthn.New(&go_webauthn.Config{
		RPID:          rp.RPID,
		RPDisplayName: rp.RPDisplayName,
		RPOrigins:     rp.RPOrigins,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("init webauthn: %w", err)
	}

	creds := make([]go_webauthn.Credential, 0, len(allowCredentialIDs))
	for _, id := range allowCredentialIDs {
		creds = append(creds, go_webauthn.Credential{ID: id})
	}

	waUser := &goWebAuthnUser{
		id:          user.ID,
		name:        user.Name,
		displayName: user.DisplayName,
		credentials: creds,
	}

	assertion, session, err := w.BeginLogin(waUser)
	if err != nil {
		return nil, nil, err
	}

	optionsBytes, err := json.Marshal(map[string]any{"publicKey": assertion.Response})
	if err != nil {
		return nil, nil, err
	}
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return json.RawMessage(optionsBytes), json.RawMessage(sessionBytes), nil
}

func (e *GoWebAuthnEngine) FinishLogin(ctx context.Context, rp WebAuthnRPConfig, user WebAuthnUser, sessionData json.RawMessage, assertionResponse json.RawMessage, storedCredentials []json.RawMessage) (json.RawMessage, error) {
	w, err := go_webauthn.New(&go_webauthn.Config{
		RPID:          rp.RPID,
		RPDisplayName: rp.RPDisplayName,
		RPOrigins:     rp.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	var session go_webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return nil, consts.VALIDATION_FAILED
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertionResponse)
	if err != nil {
		return nil, consts.VALIDATION_FAILED
	}

	creds := make([]go_webauthn.Credential, 0, len(storedCredentials))
	for _, raw := range storedCredentials {
		c, err := unmarshalStoredWebAuthnCredential(raw)
		if err != nil {
			return nil, consts.VALIDATION_FAILED
		}
		creds = append(creds, *c)
	}

	waUser := &goWebAuthnUser{
		id:          user.ID,
		name:        user.Name,
		displayName: user.DisplayName,
		credentials: creds,
	}

	cred, err := w.ValidateLogin(waUser, session, parsed)
	if err != nil {
		return nil, consts.VALIDATION_FAILED
	}

	return marshalStoredWebAuthnCredential(cred)
}

type goWebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []go_webauthn.Credential
}

func (u *goWebAuthnUser) WebAuthnID() []byte {
	return u.id
}

func (u *goWebAuthnUser) WebAuthnName() string {
	return u.name
}

func (u *goWebAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *goWebAuthnUser) WebAuthnCredentials() []go_webauthn.Credential {
	return u.credentials
}
