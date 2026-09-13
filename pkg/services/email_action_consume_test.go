package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

func TestEmailActionConsumeSucceedsOnce(t *testing.T) {
	db := newEmailActionTestDB(t)
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	service := NewEmailActionService(db, "email-action-secret").WithClock(func() time.Time { return now })
	issued := issueEmailActionForConsume(t, service, types.EmailActionPurposeSignup, types.EmailActionSecretKindCode)

	var operations int
	err := service.Consume(context.Background(), "tenant-a", types.EmailActionPurposeSignup, issued.Token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
		operations++
		return tx.Model(challenge).Update("credential_digest", "updated-by-consume").Error
	})
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if operations != 1 {
		t.Fatalf("operations = %d, want 1", operations)
	}

	var saved models.EmailActionChallenge
	if err := db.First(&saved, "id = ?", issued.ID).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if saved.ConsumedAt == nil {
		t.Fatal("challenge was not marked consumed")
	}
	if saved.CredentialDigest != "updated-by-consume" {
		t.Fatalf("operation update did not commit: %+v", saved)
	}

	if err := service.Consume(context.Background(), "tenant-a", types.EmailActionPurposeSignup, issued.Token, func(_ *gorm.DB, _ *models.EmailActionChallenge) error {
		t.Fatal("operation should not run on replay")
		return nil
	}); !errors.Is(err, consts.VALIDATION_FAILED) {
		t.Fatalf("replay error = %v, want %v", err, consts.VALIDATION_FAILED)
	}
}

func TestEmailActionConsumeWrongCodeCommitsAttempts(t *testing.T) {
	db := newEmailActionTestDB(t)
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	service := NewEmailActionService(db, "email-action-secret").WithClock(func() time.Time { return now })
	issued := issueEmailActionForConsume(t, service, types.EmailActionPurposeSignup, types.EmailActionSecretKindCode)

	wrongToken := issued.ID + ".000000"
	if err := service.Consume(context.Background(), "tenant-a", types.EmailActionPurposeSignup, wrongToken, func(_ *gorm.DB, _ *models.EmailActionChallenge) error {
		t.Fatal("operation should not run for wrong code")
		return nil
	}); !errors.Is(err, consts.BAD_CODE_VERIFIER) {
		t.Fatalf("wrong code error = %v, want %v", err, consts.BAD_CODE_VERIFIER)
	}

	var saved models.EmailActionChallenge
	if err := db.First(&saved, "id = ?", issued.ID).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if saved.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", saved.Attempts)
	}
	if saved.ConsumedAt != nil {
		t.Fatal("wrong code consumed challenge")
	}
}

func TestEmailActionConsumeRollsBackOperationFailure(t *testing.T) {
	db := newEmailActionTestDB(t)
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	service := NewEmailActionService(db, "email-action-secret").WithClock(func() time.Time { return now })
	issued := issueEmailActionForConsume(t, service, types.EmailActionPurposeRecovery, types.EmailActionSecretKindLink)
	forced := errors.New("forced operation failure")

	err := service.Consume(context.Background(), "tenant-a", types.EmailActionPurposeRecovery, issued.Token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
		if err := tx.Model(challenge).Update("credential_digest", "should-rollback").Error; err != nil {
			return err
		}
		return forced
	})
	if !errors.Is(err, forced) {
		t.Fatalf("operation error = %v, want %v", err, forced)
	}

	var saved models.EmailActionChallenge
	if err := db.First(&saved, "id = ?", issued.ID).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if saved.ConsumedAt != nil {
		t.Fatal("failed operation consumed challenge")
	}
	if saved.CredentialDigest == "should-rollback" {
		t.Fatal("operation update was not rolled back")
	}
}

func issueEmailActionForConsume(t *testing.T, service *EmailActionService, purpose types.EmailActionPurpose, kind types.EmailActionSecretKind) *types.EmailActionIssueResult {
	t.Helper()
	issued, err := service.Issue(context.Background(), types.EmailActionIssueRequest{
		InstanceID: "tenant-a",
		Purpose:    purpose,
		SecretKind: kind,
		Email:      "user@example.com",
		TTL:        10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	return issued
}
