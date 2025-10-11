package services

import (
	"context"
	"fmt"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

// AdminSessionService provides admin operations for session management
type AdminSessionService struct {
	db             *gorm.DB
	sessionService *SessionService
}

// NewAdminSessionService creates a new admin session service
func NewAdminSessionService(db *gorm.DB, sessionService *SessionService) *AdminSessionService {
	return &AdminSessionService{
		db:             db,
		sessionService: sessionService,
	}
}

// GetSessionStats returns session statistics
func (s *AdminSessionService) GetSessionStats(ctx context.Context, instanceId string) (*SessionStats, error) {
	var totalSessions, activeSessions, expiredSessions int64

	// Get database time for consistent time comparisons
	dbNow := GetDatabaseNow(s.db)

	// Get total sessions count
	if err := s.db.WithContext(ctx).Model(&models.Session{}).
		Where("instance_id = ?", instanceId).
		Count(&totalSessions).Error; err != nil {
		return nil, err
	}

	// Get active sessions count
	if err := s.db.WithContext(ctx).Model(&models.Session{}).
		Where("instance_id = ? AND (not_after IS NULL OR not_after > ?)", instanceId, dbNow).
		Count(&activeSessions).Error; err != nil {
		return nil, err
	}

	// Get expired sessions count
	if err := s.db.WithContext(ctx).Model(&models.Session{}).
		Where("instance_id = ? AND not_after IS NOT NULL AND not_after <= ?", instanceId, dbNow).
		Count(&expiredSessions).Error; err != nil {
		return nil, err
	}

	return &SessionStats{
		TotalSessions:   totalSessions,
		ActiveSessions:  activeSessions,
		ExpiredSessions: expiredSessions,
	}, nil
}

// RevokeSession revokes a specific session by sessionID
func (s *AdminSessionService) RevokeSession(ctx context.Context, instanceId, sessionID string) error {
	return s.RevokeUserSession(ctx, instanceId, sessionID)
}

// RevokeUserSession revokes a specific session and its refresh tokens
func (s *AdminSessionService) RevokeUserSession(ctx context.Context, instanceId, sessionID string) error {
	// Parse sessionID to get real ID
	realSessionID, err := GetSessionIDFromHashID(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session ID format: %w", err)
	}

	now := GetDatabaseNow(s.db)

	// Start transaction to ensure atomicity
	tx := s.db.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. Set session.not_after
	if err := tx.Model(&models.Session{}).
		Where("id = ? AND instance_id = ?", realSessionID, instanceId).
		Updates(map[string]any{
			"not_after":  now,
			"updated_at": now,
		}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// 2. Revoke all refresh tokens for this session (industry best practice)
	if err := tx.Model(&models.RefreshToken{}).
		Where("session_id = ? AND instance_id = ?", realSessionID, instanceId).
		Updates(map[string]any{
			"revoked":    true,
			"updated_at": now,
		}).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// ListAllSessions retrieves all sessions with pagination and filters
func (s *AdminSessionService) ListAllSessions(ctx context.Context, instanceId string, page, pageSize int, filters map[string]any) ([]*Session, int64, error) {
	var sessions []models.Session
	var total int64

	// Build query
	query := s.db.WithContext(ctx).Model(&models.Session{}).Where("instance_id = ?", instanceId)

	// Get database time for consistent time comparisons
	dbNow := GetDatabaseNow(s.db)

	// Apply filters
	if userID, ok := filters["user_id"]; ok {
		if userIDStr, ok := userID.(string); ok {
			realUserID, err := GetUserIDFromHashID(userIDStr)
			if err == nil {
				query = query.Where("user_id = ?", realUserID)
			}
		}
	}
	if active, ok := filters["active"]; ok {
		if fmt.Sprintf("%v", active) == "true" {
			query = query.Where("not_after IS NULL OR not_after > ?", dbNow)
		} else {
			query = query.Where("not_after IS NOT NULL AND not_after <= ?", dbNow)
		}
	}
	if fromDate, ok := filters["from_date"]; ok {
		if fromTime, ok := fromDate.(time.Time); ok {
			query = query.Where("created_at >= ?", fromTime)
		}
	}
	if toDate, ok := filters["to_date"]; ok {
		if toTime, ok := toDate.(time.Time); ok {
			query = query.Where("created_at <= ?", toTime)
		}
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get sessions with pagination
	offset := (page - 1) * pageSize
	if err := query.Order("updated_at DESC").Offset(offset).Limit(pageSize).Find(&sessions).Error; err != nil {
		return nil, 0, err
	}

	// Convert to Session
	sessionObjects := make([]*Session, len(sessions))
	for i, session := range sessions {
		sessionObj, err := NewSession(&session)
		if err != nil {
			return nil, 0, err
		}
		sessionObjects[i] = sessionObj
	}

	return sessionObjects, total, nil
}
