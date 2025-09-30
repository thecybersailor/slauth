package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

// RefreshTokenService provides database operations for RefreshToken model
type RefreshTokenService struct {
	db *gorm.DB
}

// NewRefreshTokenService creates a new refresh token service
func NewRefreshTokenService(db *gorm.DB) *RefreshTokenService {
	return &RefreshTokenService{db: db}
}

// Create creates a new refresh token
func (s *RefreshTokenService) Create(ctx context.Context, token *models.RefreshToken) error {
	return s.db.WithContext(ctx).Create(token).Error
}

// GetByToken retrieves refresh token by token string
func (s *RefreshTokenService) GetByToken(ctx context.Context, tokenString, domainCode string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := s.db.WithContext(ctx).Where("token = ? AND domain_code = ?", tokenString, domainCode).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByTokenWithSession retrieves refresh token with session information
func (s *RefreshTokenService) GetByTokenWithSession(ctx context.Context, tokenString, domainCode string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := s.db.WithContext(ctx).Preload("Session").
		Where("token = ? AND domain_code = ?", tokenString, domainCode).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetBySessionID retrieves refresh tokens by session ID
func (s *RefreshTokenService) GetBySessionID(ctx context.Context, sessionID uint, domainCode string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := s.db.WithContext(ctx).Where("session_id = ? AND domain_code = ?", sessionID, domainCode).Order("updated_at DESC").Find(&tokens).Error
	return tokens, err
}

// GetActiveBySessionID retrieves active (non-revoked) refresh tokens by session ID
func (s *RefreshTokenService) GetActiveBySessionID(ctx context.Context, sessionID uint, domainCode string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := s.db.WithContext(ctx).Where("session_id = ? AND domain_code = ? AND (revoked IS NULL OR revoked = false)",
		sessionID, domainCode).Order("updated_at DESC").Find(&tokens).Error
	return tokens, err
}

// Update updates refresh token
func (s *RefreshTokenService) Update(ctx context.Context, token *models.RefreshToken) error {
	now := time.Now()
	token.UpdatedAt = now
	return s.db.WithContext(ctx).Save(token).Error
}

// Revoke revokes a refresh token
func (s *RefreshTokenService) Revoke(ctx context.Context, tokenString, domainCode string) error {
	now := time.Now()
	result := s.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("token = ? AND domain_code = ?", tokenString, domainCode).
		Updates(map[string]any{
			"revoked":    true,
			"updated_at": now,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// RevokeBySessionID revokes all refresh tokens for a session
func (s *RefreshTokenService) RevokeBySessionID(ctx context.Context, sessionID uint, domainCode string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("session_id = ? AND domain_code = ?", sessionID, domainCode).
		Updates(map[string]any{
			"revoked":    true,
			"updated_at": now,
		}).Error
}

// RevokeByUserID revokes all refresh tokens for a user
func (s *RefreshTokenService) RevokeByUserID(ctx context.Context, userID string, domainCode string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("user_id = ? AND domain_code = ?", userID, domainCode).
		Updates(map[string]any{
			"revoked":    true,
			"updated_at": now,
		}).Error
}

// RevokeAllExcept revokes all refresh tokens for a user except one
func (s *RefreshTokenService) RevokeAllExcept(ctx context.Context, userID, domainCode, exceptToken string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("user_id = ? AND domain_code = ? AND token != ?", userID, domainCode, exceptToken).
		Updates(map[string]any{
			"revoked":    true,
			"updated_at": now,
		}).Error
}

// IsValid checks if refresh token is valid (not revoked)
func (s *RefreshTokenService) IsValid(ctx context.Context, tokenString, domainCode string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("token = ? AND domain_code = ? AND (revoked IS NULL OR revoked = false)",
			tokenString, domainCode).
		Count(&count).Error
	return count > 0, err
}

// Delete permanently deletes refresh token
func (s *RefreshTokenService) Delete(ctx context.Context, tokenString, domainCode string) error {
	return s.db.WithContext(ctx).Where("token = ? AND domain_code = ?",
		tokenString, domainCode).Delete(&models.RefreshToken{}).Error
}

// DeleteBySessionID deletes all refresh tokens for a session
func (s *RefreshTokenService) DeleteBySessionID(ctx context.Context, sessionID uint, domainCode string) error {
	return s.db.WithContext(ctx).Where("session_id = ? AND domain_code = ?",
		sessionID, domainCode).Delete(&models.RefreshToken{}).Error
}

// CleanupRevoked removes revoked refresh tokens older than specified duration
func (s *RefreshTokenService) CleanupRevoked(ctx context.Context, domainCode string, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	return s.db.WithContext(ctx).Where("domain_code = ? AND revoked = true AND updated_at < ?",
		domainCode, cutoff).Delete(&models.RefreshToken{}).Error
}

// GetTokenFamily retrieves all tokens in the same family (parent-child relationship)
func (s *RefreshTokenService) GetTokenFamily(ctx context.Context, tokenString, domainCode string) ([]models.RefreshToken, error) {
	// First get the token to find its parent or if it's a parent
	var token models.RefreshToken
	err := s.db.WithContext(ctx).Where("token = ? AND domain_code = ?", tokenString, domainCode).First(&token).Error
	if err != nil {
		return nil, err
	}

	var familyTokens []models.RefreshToken

	// If this token has a parent, get all tokens with the same parent
	if token.Parent != nil {
		err = s.db.WithContext(ctx).Where("parent = ? AND domain_code = ?", *token.Parent, domainCode).Find(&familyTokens).Error
	} else {
		// If this token is a parent, get all its children
		err = s.db.WithContext(ctx).Where("parent = ? AND domain_code = ?", tokenString, domainCode).Find(&familyTokens).Error
	}

	return familyTokens, err
}

// RevokeTokenFamily revokes all tokens in the same family
func (s *RefreshTokenService) RevokeTokenFamily(ctx context.Context, tokenString, domainCode string) error {
	// Get the token family
	familyTokens, err := s.GetTokenFamily(ctx, tokenString, domainCode)
	if err != nil {
		return err
	}

	// Revoke all tokens in the family
	now := time.Now()
	for _, familyToken := range familyTokens {
		s.db.WithContext(ctx).Model(&models.RefreshToken{}).
			Where("token = ? AND domain_code = ?", familyToken.Token, domainCode).
			Updates(map[string]any{
				"revoked":    true,
				"updated_at": now,
			})
	}

	// Also revoke the original token
	return s.Revoke(ctx, tokenString, domainCode)
}

// CountActiveTokens counts active refresh tokens for a user
func (s *RefreshTokenService) CountActiveTokens(ctx context.Context, userID, domainCode string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.RefreshToken{}).
		Where("user_id = ? AND domain_code = ? AND (revoked IS NULL OR revoked = false)",
			userID, domainCode).
		Count(&count).Error
	return count, err
}

// GetActiveTokensByUser retrieves all active refresh tokens for a user
func (s *RefreshTokenService) GetActiveTokensByUser(ctx context.Context, userID, domainCode string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := s.db.WithContext(ctx).Where("user_id = ? AND domain_code = ? AND (revoked IS NULL OR revoked = false)",
		userID, domainCode).Order("updated_at DESC").Find(&tokens).Error
	return tokens, err
}
