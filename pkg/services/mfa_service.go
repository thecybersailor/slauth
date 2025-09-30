package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

// MFAFactorService provides database operations for MFAFactor model
type MFAFactorService struct {
	db *gorm.DB
}

// NewMFAFactorService creates a new MFA factor service
func NewMFAFactorService(db *gorm.DB) *MFAFactorService {
	return &MFAFactorService{db: db}
}

// Create creates a new MFA factor
func (s *MFAFactorService) Create(ctx context.Context, factor *models.MFAFactor) error {
	return s.db.WithContext(ctx).Create(factor).Error
}

// GetByID retrieves MFA factor by ID and domain code
func (s *MFAFactorService) GetByID(ctx context.Context, id uint, domainCode string) (*models.MFAFactor, error) {
	var factor models.MFAFactor
	err := s.db.WithContext(ctx).Where("id = ? AND domain_code = ?", id, domainCode).First(&factor).Error
	if err != nil {
		return nil, err
	}
	return &factor, nil
}

// GetByUserID retrieves MFA factors by user ID
func (s *MFAFactorService) GetByUserID(ctx context.Context, userID uint, domainCode string) ([]models.MFAFactor, error) {
	var factors []models.MFAFactor
	err := s.db.WithContext(ctx).Where("user_id = ? AND domain_code = ?", userID, domainCode).Find(&factors).Error
	return factors, err
}

// GetByUserIDAndType retrieves MFA factors by user ID and type
func (s *MFAFactorService) GetByUserIDAndType(ctx context.Context, userID uint, factorType types.FactorType, domainCode string) ([]models.MFAFactor, error) {
	var factors []models.MFAFactor
	err := s.db.WithContext(ctx).Where("user_id = ? AND factor_type = ? AND domain_code = ?",
		userID, factorType, domainCode).Find(&factors).Error
	return factors, err
}

// GetVerifiedByUserID retrieves verified MFA factors by user ID
func (s *MFAFactorService) GetVerifiedByUserID(ctx context.Context, userID uint, domainCode string) ([]models.MFAFactor, error) {
	var factors []models.MFAFactor
	err := s.db.WithContext(ctx).Where("user_id = ? AND domain_code = ? AND status = ?",
		userID, domainCode, types.FactorStatusVerified).Find(&factors).Error
	return factors, err
}

// GetByUserIDAndStatus retrieves MFA factors by user ID and status
func (s *MFAFactorService) GetByUserIDAndStatus(ctx context.Context, userID uint, status types.FactorStatus, domainCode string) ([]models.MFAFactor, error) {
	var factors []models.MFAFactor
	err := s.db.WithContext(ctx).Where("user_id = ? AND status = ? AND domain_code = ?",
		userID, status, domainCode).Find(&factors).Error
	return factors, err
}

// Update updates MFA factor
func (s *MFAFactorService) Update(ctx context.Context, factor *models.MFAFactor) error {
	factor.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(factor).Error
}

// UpdateStatus updates MFA factor status
func (s *MFAFactorService) UpdateStatus(ctx context.Context, factorID uint, domainCode string, status types.FactorStatus) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.MFAFactor{}).
		Where("id = ? AND domain_code = ?", factorID, domainCode).
		Updates(map[string]any{
			"status":     status,
			"updated_at": now,
		}).Error
}

// UpdateLastChallenged updates MFA factor's last challenged timestamp
func (s *MFAFactorService) UpdateLastChallenged(ctx context.Context, factorID uint, domainCode string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.MFAFactor{}).
		Where("id = ? AND domain_code = ?", factorID, domainCode).
		Updates(map[string]any{
			"last_challenged_at": now,
			"updated_at":         now,
		}).Error
}

// Delete deletes MFA factor
func (s *MFAFactorService) Delete(ctx context.Context, factorID uint, domainCode string) error {
	return s.db.WithContext(ctx).Where("id = ? AND domain_code = ?",
		factorID, domainCode).Delete(&models.MFAFactor{}).Error
}

// CountByUserID counts MFA factors for a user
func (s *MFAFactorService) CountByUserID(ctx context.Context, userID uint, domainCode string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.MFAFactor{}).
		Where("user_id = ? AND domain_code = ?", userID, domainCode).
		Count(&count).Error
	return count, err
}

// CountVerifiedByUserID counts verified MFA factors for a user
func (s *MFAFactorService) CountVerifiedByUserID(ctx context.Context, userID uint, domainCode string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.MFAFactor{}).
		Where("user_id = ? AND domain_code = ? AND status = ?",
			userID, domainCode, types.FactorStatusVerified).
		Count(&count).Error
	return count, err
}

// MFAChallengeService provides database operations for MFAChallenge model
type MFAChallengeService struct {
	db *gorm.DB
}

// NewMFAChallengeService creates a new MFA challenge service
func NewMFAChallengeService(db *gorm.DB) *MFAChallengeService {
	return &MFAChallengeService{db: db}
}

// Create creates a new MFA challenge
func (s *MFAChallengeService) Create(ctx context.Context, challenge *models.MFAChallenge) error {
	return s.db.WithContext(ctx).Create(challenge).Error
}

// GetByID retrieves MFA challenge by ID and domain code
func (s *MFAChallengeService) GetByID(ctx context.Context, id uint, domainCode string) (*models.MFAChallenge, error) {
	var challenge models.MFAChallenge
	err := s.db.WithContext(ctx).Where("id = ? AND domain_code = ?", id, domainCode).First(&challenge).Error
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

// GetByFactorID retrieves MFA challenges by factor ID
func (s *MFAChallengeService) GetByFactorID(ctx context.Context, factorID uint, domainCode string) ([]models.MFAChallenge, error) {
	var challenges []models.MFAChallenge
	err := s.db.WithContext(ctx).Where("factor_id = ? AND domain_code = ?", factorID, domainCode).Find(&challenges).Error
	return challenges, err
}

// GetActiveByFactorID retrieves active (unverified) MFA challenges by factor ID
func (s *MFAChallengeService) GetActiveByFactorID(ctx context.Context, factorID uint, domainCode string, ttl time.Duration) ([]models.MFAChallenge, error) {
	cutoff := time.Now().Add(-ttl)
	var challenges []models.MFAChallenge
	err := s.db.WithContext(ctx).Where("factor_id = ? AND domain_code = ? AND verified_at IS NULL AND created_at > ?",
		factorID, domainCode, cutoff).Find(&challenges).Error
	return challenges, err
}

// GetWithFactor retrieves MFA challenge with factor information
func (s *MFAChallengeService) GetWithFactor(ctx context.Context, challengeID uint, domainCode string) (*models.MFAChallenge, error) {
	var challenge models.MFAChallenge
	err := s.db.WithContext(ctx).Preload("Factor").
		Where("id = ? AND domain_code = ?", challengeID, domainCode).First(&challenge).Error
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

// Update updates MFA challenge
func (s *MFAChallengeService) Update(ctx context.Context, challenge *models.MFAChallenge) error {
	return s.db.WithContext(ctx).Save(challenge).Error
}

// MarkAsVerified marks MFA challenge as verified
func (s *MFAChallengeService) MarkAsVerified(ctx context.Context, challengeID uint, domainCode string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.MFAChallenge{}).
		Where("id = ? AND domain_code = ?", challengeID, domainCode).
		Update("verified_at", now).Error
}

// Delete deletes MFA challenge
func (s *MFAChallengeService) Delete(ctx context.Context, challengeID uint, domainCode string) error {
	return s.db.WithContext(ctx).Where("id = ? AND domain_code = ?",
		challengeID, domainCode).Delete(&models.MFAChallenge{}).Error
}

// DeleteByFactorID deletes all MFA challenges for a factor
func (s *MFAChallengeService) DeleteByFactorID(ctx context.Context, factorID uint, domainCode string) error {
	return s.db.WithContext(ctx).Where("factor_id = ? AND domain_code = ?",
		factorID, domainCode).Delete(&models.MFAChallenge{}).Error
}

// CleanupExpired removes expired MFA challenges
func (s *MFAChallengeService) CleanupExpired(ctx context.Context, domainCode string, ttl time.Duration) error {
	cutoff := time.Now().Add(-ttl)
	return s.db.WithContext(ctx).Where("domain_code = ? AND created_at < ?",
		domainCode, cutoff).Delete(&models.MFAChallenge{}).Error
}

// IsValid checks if MFA challenge is valid (exists, not verified, not expired)
func (s *MFAChallengeService) IsValid(ctx context.Context, challengeID uint, domainCode string, ttl time.Duration) (bool, error) {
	cutoff := time.Now().Add(-ttl)
	var count int64
	err := s.db.WithContext(ctx).Model(&models.MFAChallenge{}).
		Where("id = ? AND domain_code = ? AND verified_at IS NULL AND created_at > ?",
			challengeID, domainCode, cutoff).
		Count(&count).Error
	return count > 0, err
}

// CountByFactorID counts MFA challenges for a factor
func (s *MFAChallengeService) CountByFactorID(ctx context.Context, factorID uint, domainCode string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.MFAChallenge{}).
		Where("factor_id = ? AND domain_code = ?", factorID, domainCode).
		Count(&count).Error
	return count, err
}

// CountActiveByFactorID counts active MFA challenges for a factor
func (s *MFAChallengeService) CountActiveByFactorID(ctx context.Context, factorID uint, domainCode string, ttl time.Duration) (int64, error) {
	cutoff := time.Now().Add(-ttl)
	var count int64
	err := s.db.WithContext(ctx).Model(&models.MFAChallenge{}).
		Where("factor_id = ? AND domain_code = ? AND verified_at IS NULL AND created_at > ?",
			factorID, domainCode, cutoff).
		Count(&count).Error
	return count, err
}
