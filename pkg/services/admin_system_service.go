package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

// AdminSystemService provides admin operations for system management
type AdminSystemService struct {
	db              *gorm.DB
	userService     *UserService
	passwordService *PasswordService
	domainCode      string
}

// NewAdminSystemService creates a new admin system service
func NewAdminSystemService(db *gorm.DB, userService *UserService, passwordService *PasswordService, domainCode string) *AdminSystemService {
	return &AdminSystemService{
		db:              db,
		userService:     userService,
		passwordService: passwordService,
		domainCode:      domainCode,
	}
}

// GetUserCount returns total number of users
func (s *AdminSystemService) GetUserCount(ctx context.Context, domainCode string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("domain_code = ? AND deleted_at IS NULL", domainCode).
		Count(&count).Error
	return count, err
}

// GetActiveSessionCount returns number of active sessions
func (s *AdminSystemService) GetActiveSessionCount(ctx context.Context, domainCode string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.Session{}).
		Where("domain_code = ? AND (not_after IS NULL OR not_after > ?)", domainCode, time.Now()).
		Count(&count).Error
	return count, err
}

// GetRecentSignups returns users who signed up in the last N days
func (s *AdminSystemService) GetRecentSignups(ctx context.Context, domainCode string, days int) ([]*User, error) {
	since := time.Now().AddDate(0, 0, -days)

	var users []models.User
	err := s.db.WithContext(ctx).Where("domain_code = ? AND created_at >= ? AND deleted_at IS NULL",
		domainCode, since).Order("updated_at DESC").Find(&users).Error
	if err != nil {
		return nil, err
	}

	// Convert to User
	userObjects := make([]*User, len(users))
	for i, user := range users {
		userObj, err := NewUser(&user, s.userService, s.passwordService, NewSessionService(s.db), s.db, s.domainCode)
		if err != nil {
			return nil, err
		}
		userObjects[i] = userObj
	}

	return userObjects, nil
}

// GetRecentSignins returns sessions created in the last N days
func (s *AdminSystemService) GetRecentSignins(ctx context.Context, domainCode string, days int) ([]*Session, error) {
	since := time.Now().AddDate(0, 0, -days)

	var sessions []models.Session
	err := s.db.WithContext(ctx).Preload("User").Where("domain_code = ? AND created_at >= ?",
		domainCode, since).Order("updated_at DESC").Find(&sessions).Error
	if err != nil {
		return nil, err
	}

	// Convert to Session
	sessionObjects := make([]*Session, len(sessions))
	for i, session := range sessions {
		sessionObj, err := NewSession(&session)
		if err != nil {
			return nil, err
		}
		sessionObjects[i] = sessionObj
	}

	return sessionObjects, nil
}
