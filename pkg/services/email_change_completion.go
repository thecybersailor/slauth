package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EmailChangeCompletionOptions struct {
	Now                time.Time
	ExcludeChallengeID string
}

func CompleteVerifiedEmailChange(ctx context.Context, db *gorm.DB, instanceID string, userID uint, originalEmail, newEmail string, opts EmailChangeCompletionOptions) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return CompleteVerifiedEmailChangeTx(tx, instanceID, userID, originalEmail, newEmail, opts)
	})
}

func CompleteVerifiedEmailChangeTx(tx *gorm.DB, instanceID string, userID uint, originalEmail, newEmail string, opts EmailChangeCompletionOptions) error {
	if tx == nil || instanceID == "" || userID == 0 || originalEmail == "" || newEmail == "" || originalEmail == newEmail {
		return consts.VALIDATION_FAILED
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	var currentUser models.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND instance_id = ?", userID, instanceID).First(&currentUser).Error; err != nil {
		return err
	}
	if currentUser.Email == nil || *currentUser.Email != originalEmail {
		return consts.VALIDATION_FAILED
	}

	var occupied int64
	if err := tx.Model(&models.User{}).
		Where("instance_id = ? AND email = ? AND id <> ?", instanceID, newEmail, userID).
		Count(&occupied).Error; err != nil {
		return err
	}
	if occupied > 0 {
		return consts.USER_ALREADY_EXISTS
	}

	result := tx.Model(&models.User{}).
		Where("id = ? AND instance_id = ? AND email = ?", userID, instanceID, originalEmail).
		Updates(map[string]any{
			"email":              newEmail,
			"email_confirmed_at": now,
			"confirmed_at":       now,
			"updated_at":         now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return consts.VALIDATION_FAILED
	}
	if err := tx.Model(&models.Session{}).
		Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)", userID, instanceID, now).
		Updates(map[string]any{"not_after": now, "updated_at": now}).Error; err != nil {
		return err
	}
	if err := tx.Model(&models.RefreshToken{}).
		Where("user_id = ? AND instance_id = ?", userID, instanceID).
		Updates(map[string]any{"revoked": true, "updated_at": now}).Error; err != nil {
		return err
	}

	query := tx.Model(&models.EmailActionChallenge{}).
		Where("instance_id = ? AND consumed_at IS NULL AND (user_id = ? OR email = ? OR original_email = ?)", instanceID, userID, originalEmail, originalEmail)
	if opts.ExcludeChallengeID != "" {
		query = query.Where("id <> ?", opts.ExcludeChallengeID)
	}
	return query.Updates(map[string]any{"consumed_at": now, "updated_at": now}).Error
}
