package services

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestEmailActionPostgresConcurrentConsumeSucceedsOnce(t *testing.T) {
	db := openEmailActionPostgresTestDB(t)
	now := time.Now().UTC()
	service := NewEmailActionService(db, "postgres-email-action-secret").WithClock(func() time.Time { return now })
	issued, err := service.Issue(t.Context(), types.EmailActionIssueRequest{
		InstanceID: "pg_email_action",
		Purpose:    types.EmailActionPurposeRecovery,
		SecretKind: types.EmailActionSecretKindLink,
		Email:      "postgres-recovery@example.com",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}

	const workers = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	errs := make([]error, 0, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := service.Consume(context.Background(), "pg_email_action", types.EmailActionPurposeRecovery, issued.Token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
				return nil
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else {
				errs = append(errs, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent consume successes = %d, want 1; errs=%v", successes, errs)
	}
	var saved models.EmailActionChallenge
	if err := db.First(&saved, "id = ?", issued.ID).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if saved.ConsumedAt == nil {
		t.Fatal("challenge was not consumed")
	}
}

func openEmailActionPostgresTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("SLAUTH_EMAIL_AUTH_TEST_DSN"))
	if dsn == "" {
		t.Skip("SLAUTH_EMAIL_AUTH_TEST_DSN is not set; skipping real PostgreSQL email action concurrency test")
	}
	schema := "slauth_email_auth_" + strings.ReplaceAll(uuid.NewString(), "-", "_")
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := admin.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() { _ = admin.Exec(`DROP SCHEMA IF EXISTS "` + schema + `" CASCADE`).Error })
	db, err := gorm.Open(postgres.Open(dsnWithSearchPath(dsn, schema)), &gorm.Config{})
	if err != nil {
		t.Fatalf("open postgres schema: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(8)
		sqlDB.SetMaxIdleConns(8)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate schema %s: %v", schema, err)
	}
	return db
}

func dsnWithSearchPath(dsn string, schema string) string {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err == nil {
			q := u.Query()
			q.Set("search_path", schema)
			u.RawQuery = q.Encode()
			return u.String()
		}
	}
	return fmt.Sprintf("%s search_path=%s", dsn, schema)
}
