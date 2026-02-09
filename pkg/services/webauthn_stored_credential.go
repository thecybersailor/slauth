package services

import (
	"encoding/base64"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	go_webauthn "github.com/go-webauthn/webauthn/webauthn"
)

type StoredWebAuthnCredentialFlags struct {
	UserPresent    bool `json:"user_present"`
	UserVerified   bool `json:"user_verified"`
	BackupEligible bool `json:"backup_eligible"`
	BackupState    bool `json:"backup_state"`
}

type StoredWebAuthnCredential struct {
	CredentialID    string                        `json:"credential_id"` // base64url
	PublicKey       string                        `json:"public_key"`    // base64url
	AttestationType string                        `json:"attestation_type,omitempty"`
	Transport       []string                      `json:"transport,omitempty"`
	AAGUID          string                        `json:"aaguid,omitempty"` // base64url
	SignCount       uint32                        `json:"sign_count,omitempty"`
	Flags           StoredWebAuthnCredentialFlags `json:"flags,omitempty"`
}

func marshalStoredWebAuthnCredential(cred *go_webauthn.Credential) (json.RawMessage, error) {
	payload := StoredWebAuthnCredential{
		CredentialID:    base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:       base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		AttestationType: cred.AttestationType,
		SignCount:       cred.Authenticator.SignCount,
		Flags: StoredWebAuthnCredentialFlags{
			UserPresent:    cred.Flags.UserPresent,
			UserVerified:   cred.Flags.UserVerified,
			BackupEligible: cred.Flags.BackupEligible,
			BackupState:    cred.Flags.BackupState,
		},
	}
	if len(cred.Authenticator.AAGUID) > 0 {
		payload.AAGUID = base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID)
	}
	if len(cred.Transport) > 0 {
		payload.Transport = make([]string, 0, len(cred.Transport))
		for _, t := range cred.Transport {
			payload.Transport = append(payload.Transport, string(t))
		}
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func unmarshalStoredWebAuthnCredential(raw json.RawMessage) (*go_webauthn.Credential, error) {
	var payload StoredWebAuthnCredential
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	id, err := base64.RawURLEncoding.DecodeString(payload.CredentialID)
	if err != nil {
		return nil, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if err != nil {
		return nil, err
	}

	var transports []protocol.AuthenticatorTransport
	for _, t := range payload.Transport {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}

	var aaguid []byte
	if payload.AAGUID != "" {
		if aaguid, err = base64.RawURLEncoding.DecodeString(payload.AAGUID); err != nil {
			return nil, err
		}
	}

	return &go_webauthn.Credential{
		ID:              id,
		PublicKey:       pub,
		AttestationType: payload.AttestationType,
		Transport:       transports,
		Flags: go_webauthn.CredentialFlags{
			UserPresent:    payload.Flags.UserPresent,
			UserVerified:   payload.Flags.UserVerified,
			BackupEligible: payload.Flags.BackupEligible,
			BackupState:    payload.Flags.BackupState,
		},
		Authenticator: go_webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: payload.SignCount,
		},
	}, nil
}
