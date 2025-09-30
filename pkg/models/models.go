package models

import (
	"github.com/flaboy/aira-core/pkg/database"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() error {
	DB = database.Database().Debug()
	return AutoMigrate(DB)
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
		&SSODomain{},
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
