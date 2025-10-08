package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

// SessionService provides database operations for Session model
type SessionService struct {
	db *gorm.DB
}

// NewSessionService creates a new session service
func NewSessionService(db *gorm.DB) *SessionService {
	return &SessionService{db: db}
}

// Create creates a new session
func (s *SessionService) Create(ctx context.Context, session *models.Session) error {
	return s.db.WithContext(ctx).Create(session).Error
}

// GetByID retrieves session by ID and instance code
func (s *SessionService) GetByID(ctx context.Context, id uint, instanceId string) (*models.Session, error) {
	var session models.Session
	err := s.db.WithContext(ctx).Where("id = ? AND instance_id = ?", id, instanceId).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// GetByUserID retrieves active session by user ID
func (s *SessionService) GetByUserID(ctx context.Context, userID uint, instanceId string) (*models.Session, error) {
	var session models.Session
	err := s.db.WithContext(ctx).Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)",
		userID, instanceId, time.Now()).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// GetWithUser retrieves session with user information
func (s *SessionService) GetWithUser(ctx context.Context, sessionID uint, instanceId string) (*models.Session, error) {
	var session models.Session
	err := s.db.WithContext(ctx).Preload("User").
		Where("id = ? AND instance_id = ?", sessionID, instanceId).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// Update updates session
func (s *SessionService) Update(ctx context.Context, session *models.Session) error {
	session.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(session).Error
}

// UpdateAAL updates session's authentication assurance level
func (s *SessionService) UpdateAAL(ctx context.Context, sessionID uint, instanceId string, aal types.AALLevel) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(map[string]any{
			"aal":        aal,
			"updated_at": now,
		}).Error
}

// UpdateAALWithExpiry updates session's authentication assurance level with expiry time
func (s *SessionService) UpdateAALWithExpiry(ctx context.Context, sessionID uint, instanceId string, aal types.AALLevel, expiresAt *time.Time) error {
	now := time.Now()
	updates := map[string]any{
		"aal":        aal,
		"updated_at": now,
	}

	if expiresAt != nil {
		updates["aal_expires_at"] = expiresAt
	}

	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(updates).Error
}

// UpdateRefreshedAt updates session's last refresh timestamp
func (s *SessionService) UpdateRefreshedAt(ctx context.Context, sessionID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(map[string]any{
			"refreshed_at": now,
			"updated_at":   now,
		}).Error
}

// SetExpiration sets session expiration time
func (s *SessionService) SetExpiration(ctx context.Context, sessionID uint, instanceId string, notAfter time.Time) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(map[string]any{
			"not_after":  notAfter,
			"updated_at": now,
		}).Error
}

// Invalidate invalidates session by setting expiration to now
func (s *SessionService) Invalidate(ctx context.Context, sessionID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(map[string]any{
			"not_after":  now,
			"updated_at": now,
		}).Error
}

// IsValid checks if session is valid (not expired)
func (s *SessionService) IsValid(ctx context.Context, sessionID uint, instanceId string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)",
			sessionID, instanceId, time.Now()).
		Count(&count).Error
	return count > 0, err
}

// CleanupExpiredSessions removes expired sessions
func (s *SessionService) CleanupExpiredSessions(ctx context.Context, instanceId string) error {
	return s.db.WithContext(ctx).Where("instance_id = ? AND not_after < ?",
		instanceId, time.Now()).Delete(&models.Session{}).Error
}

// GetSessionsByDateRange retrieves sessions within date range
func (s *SessionService) GetSessionsByDateRange(ctx context.Context, instanceId string, from, to time.Time) ([]models.Session, error) {
	var sessions []models.Session
	err := s.db.WithContext(ctx).Where("instance_id = ? AND created_at BETWEEN ? AND ?",
		instanceId, from, to).Order("updated_at DESC").Find(&sessions).Error
	return sessions, err
}

// UpdateUserAgent updates session's user agent
func (s *SessionService) UpdateUserAgent(ctx context.Context, sessionID uint, instanceId, userAgent string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(map[string]any{
			"user_agent": userAgent,
			"updated_at": now,
		}).Error
}

// UpdateIP updates session's IP address
func (s *SessionService) UpdateIP(ctx context.Context, sessionID uint, instanceId, ip string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", sessionID, instanceId).
		Updates(map[string]any{
			"ip":         ip,
			"updated_at": now,
		}).Error
}

type Session struct {
	*models.Session
	HashID string `json:"hashid"`
}

func (s *Session) GetModel() *models.Session {
	return s.Session
}
