package services

import (
	"context"
	"errors"
	"testing"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAuthServiceRunInTransactionRollsBackCreatedUser(t *testing.T) {
	db := newTransactionTestDB(t)
	service := NewAuthServiceImpl(db, newTransactionTestSecretsProvider(), "tenant-sdk-tx")

	errForcedRollback := errors.New("force rollback")
	err := service.RunInTransaction(context.Background(), func(txService AuthService) error {
		email := "tx-user@example.com"
		_, err := txService.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
			Email: &email,
		}, UserCreatedSourceAdmin, nil, nil)
		if err != nil {
			t.Fatalf("create user in transaction: %v", err)
		}

		var count int64
		if err := txService.GetDB().Model(&models.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
			t.Fatalf("count user in transaction: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected user to be visible inside transaction, got %d", count)
		}

		return errForcedRollback
	})

	if !errors.Is(err, errForcedRollback) {
		t.Fatalf("expected forced rollback error, got %v", err)
	}

	var count int64
	if err := db.Model(&models.User{}).Where("email = ?", "tx-user@example.com").Count(&count).Error; err != nil {
		t.Fatalf("count user after rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected rollback to remove user, got %d", count)
	}
}

func newTransactionTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return db
}

func newTransactionTestSecretsProvider() *StaticSecretsProvider {
	return NewStaticSecretsProvider(&types.InstanceSecrets{
		PrimaryKeyId: "test-key",
		AppSecret:    "transaction-test-app-secret",
		Keys:         map[string]*types.SigningKey{},
	})
}
