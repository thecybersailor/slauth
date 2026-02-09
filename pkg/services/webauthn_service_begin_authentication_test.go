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

type fakeWebAuthnEngine struct {
	lastAllowCredentialIDs [][]byte
	requestOptions         json.RawMessage
	sessionData            json.RawMessage
}

func (e *fakeWebAuthnEngine) BeginRegistration(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, excludeCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	return nil, nil, nil
}

func (e *fakeWebAuthnEngine) FinishRegistration(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, sessionData json.RawMessage, attestationResponse json.RawMessage) (json.RawMessage, error) {
	return nil, nil
}

func (e *fakeWebAuthnEngine) BeginLogin(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, allowCredentialIDs [][]byte) (json.RawMessage, json.RawMessage, error) {
	e.lastAllowCredentialIDs = allowCredentialIDs
	return e.requestOptions, e.sessionData, nil
}

func (e *fakeWebAuthnEngine) FinishLogin(ctx context.Context, rp services.WebAuthnRPConfig, user services.WebAuthnUser, sessionData json.RawMessage, assertionResponse json.RawMessage, storedCredentials []json.RawMessage) (json.RawMessage, error) {
	return nil, nil
}

func TestWebAuthnService_BeginAuthentication_ReturnsAvailableWhenUserHasFactors(t *testing.T) {
	t.Parallel()

	db := openSQLiteMemoryDB(t)
	if err := db.AutoMigrate(&models.AuthInstance{}, &models.User{}, &models.MFAFactor{}, &models.MFAChallenge{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	authService := services.NewAuthServiceImpl(db, newTestSecretsProvider(t), "test-instance")

	now := time.Now()
	phone := "+1234567890"
	user := &models.User{
		InstanceId: "test-instance",
		Phone:      &phone,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	credID := base64.RawURLEncoding.EncodeToString([]byte("cred-1"))
	credJSON, _ := json.Marshal(map[string]any{"credential_id": credID})
	factor := &models.MFAFactor{
		UserID:             user.ID,
		FactorType:         types.FactorTypeWebAuthn,
		Status:             types.FactorStatusVerified,
		WebAuthnCredential: (*json.RawMessage)(&credJSON),
		InstanceId:         "test-instance",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := db.Create(factor).Error; err != nil {
		t.Fatalf("create factor: %v", err)
	}

	engine := &fakeWebAuthnEngine{
		requestOptions: json.RawMessage(`{"publicKey":{"challenge":"abc"}}`),
		sessionData:    json.RawMessage(`{"challenge":"abc"}`),
	}

	svc := services.NewWebAuthnService(authService, engine)
	res, err := svc.BeginAuthentication(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, phone, "127.0.0.1")
	if err != nil {
		t.Fatalf("BeginAuthentication error: %v", err)
	}

	if !res.WebAuthnAvailable {
		t.Fatalf("expected webauthn_available=true")
	}
	if len(res.RequestOptions) == 0 {
		t.Fatalf("expected request options")
	}
	if res.ChallengeID == "" {
		t.Fatalf("expected challenge id")
	}

	if len(engine.lastAllowCredentialIDs) != 1 || string(engine.lastAllowCredentialIDs[0]) != "cred-1" {
		t.Fatalf("expected allowCredentialIDs to include cred-1, got %v", engine.lastAllowCredentialIDs)
	}
}
