package services_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type fakeWebAuthnEngineAuth struct {
	requestOptions json.RawMessage
	sessionData    json.RawMessage
	updatedCred    json.RawMessage
}

func (e *fakeWebAuthnEngineAuth) BeginRegistration(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, excludeCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	return nil, nil, nil
}

func (e *fakeWebAuthnEngineAuth) FinishRegistration(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, sessionData json.RawMessage, attestationResponse json.RawMessage) (json.RawMessage, error) {
	return nil, nil
}

func (e *fakeWebAuthnEngineAuth) BeginLogin(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, allowCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	return e.requestOptions, e.sessionData, nil
}

func (e *fakeWebAuthnEngineAuth) FinishLogin(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, sessionData json.RawMessage, assertionResponse json.RawMessage, storedCredentials []json.RawMessage) (json.RawMessage, error) {
	return e.updatedCred, nil
}

func TestWebAuthnService_FinishAuthentication_CreatesSession(t *testing.T) {
	t.Parallel()

	db := openSQLiteMemoryDB(t)
	if err := db.AutoMigrate(
		&models.AuthInstance{},
		&models.User{},
		&models.Identity{},
		&models.MFAFactor{},
		&models.MFAChallenge{},
		&models.Session{},
		&models.RefreshToken{},
		&models.MFAAMRClaim{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	authService := services.NewAuthServiceImpl(db, newTestSecretsProvider(t), "test-instance")

	now := time.Now()
	phone := "+1234567890"
	userModel := &models.User{
		InstanceId: "test-instance",
		Phone:      &phone,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := db.Create(userModel).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString([]byte("cred-1"))
	credJSON := json.RawMessage([]byte(`{"credential_id":"` + credIDB64 + `"}`))
	factor := &models.MFAFactor{
		UserID:             userModel.ID,
		FactorType:         types.FactorTypeWebAuthn,
		Status:             types.FactorStatusVerified,
		WebAuthnCredential: &credJSON,
		InstanceId:         "test-instance",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := db.Create(factor).Error; err != nil {
		t.Fatalf("create factor: %v", err)
	}

	engine := &fakeWebAuthnEngineAuth{
		requestOptions: json.RawMessage(`{"publicKey":{"challenge":"abc"}}`),
		sessionData:    json.RawMessage(`{"challenge":"abc"}`),
		updatedCred:    credJSON,
	}
	svc := services.NewWebAuthnService(authService, engine)

	beginRes, err := svc.BeginAuthentication(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, phone, "127.0.0.1")
	if err != nil {
		t.Fatalf("BeginAuthentication error: %v", err)
	}
	if !beginRes.WebAuthnAvailable || beginRes.ChallengeID == "" {
		t.Fatalf("unexpected begin result: %+v", beginRes)
	}

	finishRes, err := svc.FinishAuthentication(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, beginRes.ChallengeID, json.RawMessage(`{"assertion":"x"}`), "test-ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("FinishAuthentication error: %v", err)
	}
	if finishRes.AccessToken == "" || finishRes.RefreshToken == "" {
		t.Fatalf("expected tokens, got %+v", finishRes)
	}
}
