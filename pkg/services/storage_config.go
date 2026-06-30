package services

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"gorm.io/gorm"
)

type StorageConfig struct {
	Schema string
}

func (c StorageConfig) normalized() (StorageConfig, error) {
	c.Schema = strings.TrimSpace(c.Schema)
	if c.Schema == "" {
		return c, nil
	}
	if err := validatePostgresIdentifier(c.Schema); err != nil {
		return c, err
	}
	return c, nil
}

func (c StorageConfig) applyTransactionScope(tx *gorm.DB) error {
	c, err := c.normalized()
	if err != nil {
		return err
	}
	if c.Schema == "" || tx == nil || tx.Dialector == nil || tx.Name() != "postgres" {
		return nil
	}
	return tx.Exec(fmt.Sprintf("SET LOCAL search_path TO %s, public", quotePostgresIdentifier(c.Schema))).Error
}

func RunInStorageTransaction(ctx context.Context, db *gorm.DB, storageConfig StorageConfig, fn func(tx *gorm.DB) error) error {
	if db == nil {
		return fmt.Errorf("slauth: nil db")
	}
	if fn == nil {
		return fmt.Errorf("slauth: nil storage transaction callback")
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := storageConfig.applyTransactionScope(tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

func validatePostgresIdentifier(value string) error {
	for _, r := range value {
		if r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return fmt.Errorf("slauth: invalid storage schema %q", value)
	}
	return nil
}

func quotePostgresIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
