package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestEmailActionDigestIsPurposeBound(t *testing.T) {
	a := emailActionDigest("test-key", "instance-a", "signup", "challenge-a", "123456")
	b := emailActionDigest("test-key", "instance-a", "recovery", "challenge-a", "123456")
	if a == b {
		t.Fatal("cross-purpose digest collision")
	}
	if a == "123456" || strings.Contains(a, "123456") {
		t.Fatal("plaintext code stored")
	}
}

func TestEmailActionIssueStoresOnlyDigest(t *testing.T) {
	db := newEmailActionTestDB(t)
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	service := NewEmailActionService(db, "email-action-secret").WithClock(func() time.Time { return now })

	result, err := service.Issue(context.Background(), types.EmailActionIssueRequest{
		InstanceID: "tenant-a",
		Purpose:    types.EmailActionPurposeRecovery,
		SecretKind: types.EmailActionSecretKindLink,
		Email:      "User@Example.COM ",
		TTL:        30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if result.ID == "" || result.Secret == "" || result.Token != result.ID+"."+result.Secret {
		t.Fatalf("unexpected issue result: %+v", result)
	}

	var saved models.EmailActionChallenge
	if err := db.First(&saved, "id = ?", result.ID).Error; err != nil {
		t.Fatalf("load saved challenge: %v", err)
	}
	if saved.SecretDigest == "" || strings.Contains(saved.SecretDigest, result.Secret) {
		t.Fatalf("secret digest leaked secret: %+v", saved)
	}
	if saved.Email != "user@example.com" {
		t.Fatalf("email = %q, want normalized user@example.com", saved.Email)
	}
	if !saved.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("expires_at = %s", saved.ExpiresAt)
	}
}

func TestEmailActionJSONDoesNotExposeSecrets(t *testing.T) {
	pending := "pending-hash"
	challenge := models.EmailActionChallenge{
		ID:                  "challenge-id",
		SecretDigest:        "secret-digest-marker",
		PendingPasswordHash: &pending,
		CredentialDigest:    "credential-digest-marker",
	}
	payload, err := json.Marshal(challenge)
	if err != nil {
		t.Fatalf("marshal challenge: %v", err)
	}
	for _, secret := range []string{"secret-digest-marker", "pending-hash", "credential-digest-marker"} {
		if strings.Contains(string(payload), secret) {
			t.Fatalf("secret %q leaked in JSON %s", secret, payload)
		}
	}
}

func newEmailActionTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/slauth-email-action.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	return db
}
