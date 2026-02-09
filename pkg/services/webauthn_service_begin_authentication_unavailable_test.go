package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
)

func TestWebAuthnService_BeginAuthentication_ReturnsUnavailableWhenUserNotFound(t *testing.T) {
	t.Parallel()

	db := openSQLiteMemoryDB(t)
	if err := db.AutoMigrate(&models.AuthInstance{}, &models.User{}, &models.MFAFactor{}, &models.MFAChallenge{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	authService := services.NewAuthServiceImpl(db, newTestSecretsProvider(t), "test-instance")

	engine := &fakeWebAuthnEngine{}
	svc := services.NewWebAuthnService(authService, engine)

	res, err := svc.BeginAuthentication(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, "+000", "127.0.0.1")
	if err != nil {
		t.Fatalf("BeginAuthentication error: %v", err)
	}
	if res.WebAuthnAvailable {
		t.Fatalf("expected webauthn_available=false")
	}
}

func TestWebAuthnService_BeginAuthentication_ReturnsUnavailableWhenNoWebAuthnFactors(t *testing.T) {
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

	engine := &fakeWebAuthnEngine{}
	svc := services.NewWebAuthnService(authService, engine)

	res, err := svc.BeginAuthentication(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, phone, "127.0.0.1")
	if err != nil {
		t.Fatalf("BeginAuthentication error: %v", err)
	}
	if res.WebAuthnAvailable {
		t.Fatalf("expected webauthn_available=false")
	}
}
