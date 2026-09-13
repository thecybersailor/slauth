package models

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestEmailActionMigrationIsRepeatable(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/slauth-email-action-model.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if !db.Migrator().HasTable((&EmailActionChallenge{}).TableName()) {
		t.Fatal("email action challenge table was not migrated")
	}
}
