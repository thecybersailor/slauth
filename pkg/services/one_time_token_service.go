package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

// OneTimeTokenService provides database operations for OneTimeToken model
type OneTimeTokenService struct {
	db *gorm.DB
}

// NewOneTimeTokenService creates a new one-time token service
func NewOneTimeTokenService(db *gorm.DB) *OneTimeTokenService {
	return &OneTimeTokenService{db: db}
}

// Create creates a new one-time token
func (s *OneTimeTokenService) Create(ctx context.Context, token *models.OneTimeToken) error {
	return s.db.WithContext(ctx).Create(token).Error
}

// GetByTokenHash retrieves one-time token by token hash
func (s *OneTimeTokenService) GetByTokenHash(ctx context.Context, tokenHash, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("token_hash = ? AND instance_id = ?", tokenHash, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByUserIDAndType retrieves one-time token by user ID and type
func (s *OneTimeTokenService) GetByUserIDAndType(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("user_id = ? AND token_type = ? AND instance_id = ?",
		userID, tokenType, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByUserIDAndTypeAndRelatesTo retrieves one-time token by user ID, type, and relates_to
func (s *OneTimeTokenService) GetByUserIDAndTypeAndRelatesTo(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, relatesTo, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("user_id = ? AND token_type = ? AND relates_to = ? AND instance_id = ?",
		userID, tokenType, relatesTo, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByEmailAndType retrieves one-time token by email and type
func (s *OneTimeTokenService) GetByEmailAndType(ctx context.Context, email string, tokenType types.OneTimeTokenType, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("email = ? AND token_type = ? AND instance_id = ?",
		email, tokenType, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByEmailAndTypeAndSessionCode retrieves one-time token by email, type and session code
func (s *OneTimeTokenService) GetByEmailAndTypeAndSessionCode(ctx context.Context, email string, tokenType types.OneTimeTokenType, sessionCode, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("email = ? AND token_type = ? AND session_code = ? AND instance_id = ?",
		email, tokenType, sessionCode, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByPhoneAndType retrieves one-time token by phone and type
func (s *OneTimeTokenService) GetByPhoneAndType(ctx context.Context, phone string, tokenType types.OneTimeTokenType, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("phone = ? AND token_type = ? AND instance_id = ?",
		phone, tokenType, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByPhoneAndTypeAndSessionCode retrieves one-time token by phone, type and session code
func (s *OneTimeTokenService) GetByPhoneAndTypeAndSessionCode(ctx context.Context, phone string, tokenType types.OneTimeTokenType, sessionCode, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("phone = ? AND token_type = ? AND session_code = ? AND instance_id = ?",
		phone, tokenType, sessionCode, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// DeleteByEmailAndType deletes one-time token by email and type
func (s *OneTimeTokenService) DeleteByEmailAndType(ctx context.Context, email string, tokenType types.OneTimeTokenType, instanceId string) error {
	return s.db.WithContext(ctx).Where("email = ? AND token_type = ? AND instance_id = ?",
		email, tokenType, instanceId).Delete(&models.OneTimeToken{}).Error
}

// DeleteByPhoneAndType deletes one-time token by phone and type
func (s *OneTimeTokenService) DeleteByPhoneAndType(ctx context.Context, phone string, tokenType types.OneTimeTokenType, instanceId string) error {
	return s.db.WithContext(ctx).Where("phone = ? AND token_type = ? AND instance_id = ?",
		phone, tokenType, instanceId).Delete(&models.OneTimeToken{}).Error
}

// GetActiveByUserIDAndType retrieves active (non-expired) one-time token by user ID and type
func (s *OneTimeTokenService) GetActiveByUserIDAndType(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, instanceId string, ttl time.Duration) (*models.OneTimeToken, error) {
	cutoff := time.Now().Add(-ttl)
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Where("user_id = ? AND token_type = ? AND instance_id = ? AND created_at > ?",
		userID, tokenType, instanceId, cutoff).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetWithUser retrieves one-time token with user information
func (s *OneTimeTokenService) GetWithUser(ctx context.Context, tokenHash, instanceId string) (*models.OneTimeToken, error) {
	var token models.OneTimeToken
	err := s.db.WithContext(ctx).Preload("User").
		Where("token_hash = ? AND instance_id = ?", tokenHash, instanceId).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// Update updates one-time token
func (s *OneTimeTokenService) Update(ctx context.Context, token *models.OneTimeToken) error {
	token.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(token).Error
}

// Delete deletes one-time token
func (s *OneTimeTokenService) Delete(ctx context.Context, tokenHash, instanceId string) error {
	return s.db.WithContext(ctx).Where("token_hash = ? AND instance_id = ?",
		tokenHash, instanceId).Delete(&models.OneTimeToken{}).Error
}

// DeleteByID deletes one-time token by ID
func (s *OneTimeTokenService) DeleteByID(ctx context.Context, id uint, instanceId string) error {
	return s.db.WithContext(ctx).Where("id = ? AND instance_id = ?",
		id, instanceId).Delete(&models.OneTimeToken{}).Error
}

// DeleteByUserIDAndType deletes one-time tokens by user ID and type
func (s *OneTimeTokenService) DeleteByUserIDAndType(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, instanceId string) error {
	return s.db.WithContext(ctx).Where("user_id = ? AND token_type = ? AND instance_id = ?",
		userID, tokenType, instanceId).Delete(&models.OneTimeToken{}).Error
}

// DeleteExpired deletes expired one-time tokens
func (s *OneTimeTokenService) DeleteExpired(ctx context.Context, instanceId string, ttl time.Duration) error {
	cutoff := time.Now().Add(-ttl)
	return s.db.WithContext(ctx).Where("instance_id = ? AND created_at < ?",
		instanceId, cutoff).Delete(&models.OneTimeToken{}).Error
}

// IsValid checks if one-time token is valid (exists and not expired)
func (s *OneTimeTokenService) IsValid(ctx context.Context, tokenHash, instanceId string, ttl time.Duration) (bool, error) {
	cutoff := time.Now().Add(-ttl)
	var count int64
	err := s.db.WithContext(ctx).Model(&models.OneTimeToken{}).
		Where("token_hash = ? AND instance_id = ? AND created_at > ?",
			tokenHash, instanceId, cutoff).
		Count(&count).Error
	return count > 0, err
}

// CountByUserIDAndType counts one-time tokens by user ID and type
func (s *OneTimeTokenService) CountByUserIDAndType(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, instanceId string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.OneTimeToken{}).
		Where("user_id = ? AND token_type = ? AND instance_id = ?",
			userID, tokenType, instanceId).
		Count(&count).Error
	return count, err
}

// CountActiveByUserIDAndType counts active (non-expired) one-time tokens by user ID and type
func (s *OneTimeTokenService) CountActiveByUserIDAndType(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, instanceId string, ttl time.Duration) (int64, error) {
	cutoff := time.Now().Add(-ttl)
	var count int64
	err := s.db.WithContext(ctx).Model(&models.OneTimeToken{}).
		Where("user_id = ? AND token_type = ? AND instance_id = ? AND created_at > ?",
			userID, tokenType, instanceId, cutoff).
		Count(&count).Error
	return count, err
}

// GetByType retrieves all one-time tokens by type
func (s *OneTimeTokenService) GetByType(ctx context.Context, tokenType types.OneTimeTokenType, instanceId string) ([]models.OneTimeToken, error) {
	var tokens []models.OneTimeToken
	err := s.db.WithContext(ctx).Where("token_type = ? AND instance_id = ?",
		tokenType, instanceId).Find(&tokens).Error
	return tokens, err
}

// GetByUserID retrieves all one-time tokens for a user
func (s *OneTimeTokenService) GetByUserID(ctx context.Context, userID uint, instanceId string) ([]models.OneTimeToken, error) {
	var tokens []models.OneTimeToken
	err := s.db.WithContext(ctx).Where("user_id = ? AND instance_id = ?",
		userID, instanceId).Find(&tokens).Error
	return tokens, err
}

// GetActiveByUserID retrieves all active (non-expired) one-time tokens for a user
func (s *OneTimeTokenService) GetActiveByUserID(ctx context.Context, userID uint, instanceId string, ttl time.Duration) ([]models.OneTimeToken, error) {
	cutoff := time.Now().Add(-ttl)
	var tokens []models.OneTimeToken
	err := s.db.WithContext(ctx).Where("user_id = ? AND instance_id = ? AND created_at > ?",
		userID, instanceId, cutoff).Find(&tokens).Error
	return tokens, err
}

// CleanupExpiredTokens removes expired tokens for all types
func (s *OneTimeTokenService) CleanupExpiredTokens(ctx context.Context, instanceId string) error {
	// Define TTL for different token types
	tokenTTLs := map[types.OneTimeTokenType]time.Duration{
		types.OneTimeTokenTypeConfirmation:       24 * time.Hour,
		types.OneTimeTokenTypeReauthentication:   5 * time.Minute,
		types.OneTimeTokenTypeRecovery:           24 * time.Hour,
		types.OneTimeTokenTypeEmailChangeNew:     24 * time.Hour,
		types.OneTimeTokenTypeEmailChangeCurrent: 24 * time.Hour,
		types.OneTimeTokenTypePhoneChange:        24 * time.Hour,
	}

	for tokenType, ttl := range tokenTTLs {
		cutoff := time.Now().Add(-ttl)
		err := s.db.WithContext(ctx).Where("token_type = ? AND instance_id = ? AND created_at < ?",
			tokenType, instanceId, cutoff).Delete(&models.OneTimeToken{}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// ReplaceToken replaces an existing token with a new one (atomic operation)
func (s *OneTimeTokenService) ReplaceToken(ctx context.Context, userID uint, tokenType types.OneTimeTokenType, relatesTo, newTokenHash, instanceId string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete existing token
		err := tx.Where("user_id = ? AND token_type = ? AND relates_to = ? AND instance_id = ?",
			userID, tokenType, relatesTo, instanceId).Delete(&models.OneTimeToken{}).Error
		if err != nil {
			return err
		}

		// Create new token
		now := time.Now()
		newToken := &models.OneTimeToken{
			UserID:     &userID,
			TokenType:  tokenType,
			TokenHash:  newTokenHash,
			RelatesTo:  relatesTo,
			InstanceId: instanceId,
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		return tx.Create(newToken).Error
	})
}
