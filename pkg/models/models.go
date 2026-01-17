package models

import (
	"log/slog"

	"github.com/flaboy/aira-core/pkg/database"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() error {
	DB = database.Database()
	return AutoMigrate(DB)
}

type TableModel interface {
	TableName() string
}

var tableNamePrefix *string

// SetDefaultTablePrefix sets the global table name prefix for all models
// This should only be called during initialization, before any table migration.
// If called multiple times, only the first call takes effect and subsequent calls are ignored with a warning.
func SetDefaultTablePrefix(prefix string) {
	if tableNamePrefix != nil {
		slog.Warn("SetDefaultTablePrefix called multiple times, ignoring",
			"oldPrefix", *tableNamePrefix,
			"newPrefix", prefix)
		return
	}
	tableNamePrefix = &prefix
}

func getTableName(tableName string) string {
	if tableNamePrefix != nil {
		return *tableNamePrefix + tableName
	}
	return tableName
}

// AllModels returns a slice of all auth models for migration purposes
func AllModels() []interface{} {
	return []interface{}{
		&User{},
		&Identity{},
		&Session{},
		&RefreshToken{},
		&MFAFactor{},
		&MFAChallenge{},
		&MFAAMRClaim{},
		&OneTimeToken{},
		&FlowState{},
		&SAMLRelayState{},
		&SSOProvider{},
		&SAMLProvider{},
		&SSOInstance{},
		&AuthInstance{},
	}
}

// AutoMigrate runs auto migration for all auth models
func AutoMigrate(db *gorm.DB) error {
	db.DisableForeignKeyConstraintWhenMigrating = true
	return db.AutoMigrate(AllModels()...)
}

// CreateSchema creates the auth schema if it doesn't exist
func CreateSchema(db *gorm.DB) error {
	return db.Exec("CREATE SCHEMA IF NOT EXISTS auth").Error
}
