package services_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
)

type fakeWebAuthnEngineRegistration struct {
	creationOptions  json.RawMessage
	sessionData      json.RawMessage
	storedCredential json.RawMessage
}

func (e *fakeWebAuthnEngineRegistration) BeginRegistration(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, excludeCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	return e.creationOptions, e.sessionData, nil
}

func (e *fakeWebAuthnEngineRegistration) FinishRegistration(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, sessionData json.RawMessage, attestationResponse json.RawMessage) (json.RawMessage, error) {
	return e.storedCredential, nil
}

func (e *fakeWebAuthnEngineRegistration) BeginLogin(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, allowCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	return nil, nil, nil
}

func (e *fakeWebAuthnEngineRegistration) FinishLogin(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, sessionData json.RawMessage, assertionResponse json.RawMessage, storedCredentials []json.RawMessage) (json.RawMessage, error) {
	return nil, nil
}

func TestWebAuthnService_BeginAndFinishRegistration_StoresCredential(t *testing.T) {
	t.Parallel()

	db := openSQLiteMemoryDB(t)
	if err := db.AutoMigrate(
		&models.AuthInstance{},
		&models.User{},
		&models.Identity{},
		&models.MFAFactor{},
		&models.MFAChallenge{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	authService := services.NewAuthServiceImpl(db, newTestSecretsProvider(t), "test-instance")

	now := time.Now()
	email := "u@example.com"
	userModel := &models.User{
		InstanceId: "test-instance",
		Email:      &email,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := db.Create(userModel).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	userHashID, err := services.GenerateUserHashID(userModel.ID)
	if err != nil {
		t.Fatalf("hash user id: %v", err)
	}
	userObj, err := authService.GetUserService().GetByHashID(context.Background(), userHashID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	engine := &fakeWebAuthnEngineRegistration{
		creationOptions:  json.RawMessage(`{"publicKey":{"challenge":"reg"}}`),
		sessionData:      json.RawMessage(`{"challenge":"reg"}`),
		storedCredential: json.RawMessage(`{"credential_id":"Y3JlZC0x"}`),
	}
	svc := services.NewWebAuthnService(authService, engine)

	beginRes, err := svc.BeginRegistration(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, userObj, "My Passkey", "127.0.0.1")
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}
	if beginRes.FactorID == "" || beginRes.ChallengeID == "" || len(beginRes.CreationOptions) == 0 {
		t.Fatalf("unexpected begin result: %+v", beginRes)
	}

	finishRes, err := svc.FinishRegistration(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, beginRes.ChallengeID, json.RawMessage(`{"attestation":"x"}`))
	if err != nil {
		t.Fatalf("FinishRegistration error: %v", err)
	}
	if !finishRes.Success {
		t.Fatalf("expected success=true")
	}
}
