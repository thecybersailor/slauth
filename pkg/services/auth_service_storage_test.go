package services

import (
	"context"
	"testing"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAuthServiceStorageConfigIsPerServiceAndTransactionScoped(t *testing.T) {
	db := newStorageConfigTestDB(t)
	secrets := newTransactionTestSecretsProvider()

	serviceA := NewAuthServiceImplWithStorage(db, secrets, "tenant-a", StorageConfig{Schema: "auth_a"})
	serviceB := NewAuthServiceImplWithStorage(db, secrets, "tenant-b", StorageConfig{Schema: "auth_b"})

	if got := serviceA.StorageConfig().Schema; got != "auth_a" {
		t.Fatalf("service A schema = %q, want auth_a", got)
	}
	if got := serviceB.StorageConfig().Schema; got != "auth_b" {
		t.Fatalf("service B schema = %q, want auth_b", got)
	}

	if err := serviceA.RunInTransaction(context.Background(), func(txService AuthService) error {
		txImpl, ok := txService.(*AuthServiceImpl)
		if !ok {
			t.Fatalf("transaction service type = %T, want *AuthServiceImpl", txService)
		}
		if got := txImpl.StorageConfig().Schema; got != "auth_a" {
			t.Fatalf("transaction schema = %q, want auth_a", got)
		}
		if got := serviceB.StorageConfig().Schema; got != "auth_b" {
			t.Fatalf("service B schema changed to %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("run transaction: %v", err)
	}
}

func TestRunInStorageTransactionPassesTransactionDB(t *testing.T) {
	db := newStorageConfigTestDB(t)
	called := false

	err := RunInStorageTransaction(context.Background(), db, StorageConfig{Schema: "auth_tx"}, func(tx *gorm.DB) error {
		called = true
		if tx == nil {
			t.Fatalf("transaction db is nil")
		}
		return tx.Create(&models.AuthInstance{
			InstanceId: "tenant-storage-tx",
			ConfigData: config.NewDefaultAuthServiceConfig(),
		}).Error
	})
	if err != nil {
		t.Fatalf("run storage transaction: %v", err)
	}
	if !called {
		t.Fatalf("transaction callback was not called")
	}

	var count int64
	if err := db.Model(&models.AuthInstance{}).Where("instance_id = ?", "tenant-storage-tx").Count(&count).Error; err != nil {
		t.Fatalf("count created auth instance: %v", err)
	}
	if count != 1 {
		t.Fatalf("auth instance count = %d, want 1", count)
	}
}

func newStorageConfigTestDB(t *testing.T) *gorm.DB {
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
