package services_test

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func openSQLiteMemoryDB(t *testing.T) *gorm.DB {
	t.Helper()

	// Use a unique in-memory database per test to avoid cross-test locking when
	// running in parallel.
	dsn := fmt.Sprintf("file:%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}
