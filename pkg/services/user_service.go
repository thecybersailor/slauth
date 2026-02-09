package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// getAppSecret Get global AppSecret
func getAppSecret() string {
	if globalHashIDService != nil {
		return globalHashIDService.appSecret
	}
	return ""
}

// getDefaultPasswordStrengthScore Get default password strength score
func getDefaultPasswordStrengthScore() int {
	return 2 // Default requires zxcvbn score >= 2
}

// UserService provides database operations for User model
type UserService struct {
	db              *gorm.DB
	instanceId      string
	passwordService *PasswordService
	authService     AuthService // 用于访问middlewares
}

// NewUserService creates a new user service
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db, instanceId: ""}
}

// NewUserServiceWithInstance creates a new user service with instance code
func NewUserServiceWithInstance(db *gorm.DB, instanceId string) *UserService {
	return &UserService{
		db:         db,
		instanceId: instanceId,
	}
}

// SetPasswordService sets the password service (chainable)
func (s *UserService) SetPasswordService(passwordService *PasswordService) *UserService {
	s.passwordService = passwordService
	return s
}

// SetAuthService sets the auth service (chainable)
func (s *UserService) SetAuthService(authService AuthService) *UserService {
	s.authService = authService
	return s
}

// UserCreateOptions defines options for creating a user
type UserCreateOptions struct {
	Username     *string        // Optional: username for username-based authentication
	Email        *string        // Optional: email address for email-based authentication
	Phone        *string        // Optional: phone number for phone-based authentication
	Password     *string        // Optional: password (not required for OAuth/anonymous users)
	UserMetadata map[string]any // Optional: user metadata (stored in raw_user_meta_data)
	AppMetadata  map[string]any // Optional: app metadata (stored in raw_app_meta_data)
}

// Create creates a new user
func (s *UserService) Create(ctx context.Context, user *models.User) error {
	return s.db.WithContext(ctx).Create(user).Error
}

// CreateUser creates a new user with options (defaults to signup source)
func (s *UserService) CreateUser(ctx context.Context, opts *UserCreateOptions) (*User, error) {
	return s.CreateUserWithSource(ctx, opts, UserCreatedSourceSignup, nil, nil)
}

// CreateUserWithSource creates a new user with source information and hooks support
func (s *UserService) CreateUserWithSource(
	ctx context.Context,
	opts *UserCreateOptions,
	source UserCreatedSource,
	extraContext map[string]any, // 存储Provider、Identity等额外信息
	httpRequest *http.Request, // HTTP请求（可选）
) (*User, error) {
	var createdUser *User
	var userModel *models.User

	// 在事务中执行
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. 参数验证（现有逻辑）
		passwordService := s.passwordService
		if passwordService == nil {
			passwordService = NewPasswordService(nil, getAppSecret(), getDefaultPasswordStrengthScore())
		}

		validator := NewValidatorService()

		username := ""
		email := ""
		phone := ""
		if opts.Username != nil {
			username = *opts.Username
		}
		if opts.Email != nil {
			email = *opts.Email
		}
		if opts.Phone != nil {
			phone = *opts.Phone
		}

		// Validate username format if provided
		if username != "" {
			if len(username) < 1 {
				return errors.New("username cannot be empty")
			}
		}

		// Validate email format if provided
		if email != "" {
			if err := validator.ValidateEmail(email); err != nil {
				return err
			}
			email = validator.SanitizeEmail(email)
		}

		// Validate phone format if provided
		if phone != "" {
			if err := validator.ValidatePhone(phone); err != nil {
				return err
			}
			phone = validator.SanitizePhone(phone)
		}

		// Validate password strength if provided
		var password string
		if opts.Password != nil {
			password = *opts.Password
			if password != "" {
				if err := validator.ValidatePassword(password); err != nil {
					return err
				}

				valid := passwordService.ValidatePasswordStrength(password)
				if !valid {
					slog.Error("Password strength validation failed")
					return consts.WEAK_PASSWORD
				}
			}
		}

		// Check for duplicate username
		if username != "" {
			var existingUser models.User
			err := tx.WithContext(ctx).Where("username = ? AND instance_id = ?", username, s.instanceId).First(&existingUser).Error
			if err == nil {
				return consts.USER_ALREADY_EXISTS
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}

		// Check for duplicate email
		if email != "" {
			var existingUser models.User
			err := tx.WithContext(ctx).Where("email = ? AND instance_id = ?", email, s.instanceId).First(&existingUser).Error
			if err == nil {
				return consts.USER_ALREADY_EXISTS
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}

		// Check for duplicate phone
		if phone != "" {
			var existingUser models.User
			err := tx.WithContext(ctx).Where("phone = ? AND instance_id = ?", phone, s.instanceId).First(&existingUser).Error
			if err == nil {
				return consts.USER_ALREADY_EXISTS
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}

		// Hash password if provided
		var hashedPassword *string
		if password != "" {
			hashed, err := passwordService.HashPassword(password)
			if err != nil {
				return err
			}
			hashedPassword = &hashed
		}

		// Serialize user metadata
		var userMetaJSON *json.RawMessage
		if len(opts.UserMetadata) > 0 {
			metaBytes, err := json.Marshal(opts.UserMetadata)
			if err != nil {
				return err
			}
			userMetaJSON = (*json.RawMessage)(&metaBytes)
		}

		// Serialize app metadata
		var appMetaJSON *json.RawMessage
		if len(opts.AppMetadata) > 0 {
			metaBytes, err := json.Marshal(opts.AppMetadata)
			if err != nil {
				return err
			}
			appMetaJSON = (*json.RawMessage)(&metaBytes)
		}

		// 2. 构建userModel（现有逻辑）
		now := time.Now()
		userModel = &models.User{
			InstanceId:        s.instanceId,
			Username:          &username,
			Email:             &email,
			Phone:             &phone,
			EncryptedPassword: hashedPassword,
			RawUserMetaData:   (*models.JSON)(userMetaJSON),
			RawAppMetaData:    (*models.JSON)(appMetaJSON),
			CreatedAt:         now,
			UpdatedAt:         now,
			IsAnonymous:       false,
		}

		// Set username/email/phone to nil if empty
		if username == "" {
			userModel.Username = nil
		}
		if email == "" {
			userModel.Email = nil
		}
		if phone == "" {
			userModel.Phone = nil
		}

		// 3. 执行 BeforeUserCreatedUse middlewares
		if err := s.executeBeforeUserCreatedMiddlewares(ctx, tx, userModel, source, opts, extraContext, httpRequest); err != nil {
			return err // 事务回滚
		}

		// 4. 创建用户
		if err := tx.WithContext(ctx).Create(userModel).Error; err != nil {
			return err
		}

		// 5. 构建User对象
		user, err := NewUserFromModel(userModel, passwordService, NewSessionService(tx), tx, s.instanceId)
		if err != nil {
			return err
		}
		createdUser = user

		// 6. 执行 AfterUserCreatedUse middlewares
		if err := s.executeAfterUserCreatedMiddlewares(ctx, tx, user, source, extraContext, httpRequest); err != nil {
			return err // 事务回滚（user会被删除）
		}

		// 7. 如果有 identity，在事务中创建（用于 OAuth）
		if identity, ok := extraContext["identity"].(*models.Identity); ok && identity != nil {
			identity.UserID = user.ID
			if err := tx.WithContext(ctx).Create(identity).Error; err != nil {
				slog.Error("[CreateUserWithSource] Failed to create identity", "error", err)
				return err // 事务回滚
			}
			// 直接关联到 user，避免事务外查询
			user.Identities = []models.Identity{*identity}

			// 触发 IdentityLinkedUse middleware
			if s.authService != nil {
				if authServiceImpl, ok := s.authService.(*AuthServiceImpl); ok {
					if err := authServiceImpl.ExecuteIdentityLinkedMiddlewares(
						ctx,
						user,
						identity,
						extraContext["provider"].(string),
						true, // isNewIdentity
						httpRequest,
					); err != nil {
						slog.Error("IdentityLinkedUse middleware failed", "error", err)
						return err // 事务回滚
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// 修复：事务提交后，将 user.db 从已提交的事务 tx 切换为正常的 db 连接
	createdUser.db = s.db

	return createdUser, nil
}

// GetByID retrieves user by ID and instance code
func (s *UserService) GetByID(ctx context.Context, id uint, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Where("id = ? AND instance_id = ?", id, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByUsername retrieves user by username and instance code
func (s *UserService) GetByUsername(ctx context.Context, username, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Where("username = ? AND instance_id = ?", username, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByPhone retrieves user by phone and instance code
func (s *UserService) GetByPhone(ctx context.Context, phone, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Where("phone = ? AND instance_id = ?", phone, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByEmailOrPhone retrieves user by email or phone and instance code
func (s *UserService) GetByEmailOrPhone(ctx context.Context, emailOrPhone, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Where("(email = ? OR phone = ?) AND instance_id = ?",
		emailOrPhone, emailOrPhone, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByIdentifier retrieves user by username, email or phone and instance code
func (s *UserService) GetByIdentifier(ctx context.Context, identifier, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Where("(username = ? OR email = ? OR phone = ?) AND instance_id = ?",
		identifier, identifier, identifier, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByHashID retrieves user by hashid and instance code
func (s *UserService) GetByHashID(ctx context.Context, hashID string) (*User, error) {
	return GetUserByHashID(ctx, s.db, s.instanceId, hashID)
}

// GetByEmail retrieves user by email and instance code
func (s *UserService) GetByEmail(ctx context.Context, email string) (*User, error) {
	return GetUserByEmail(ctx, s.db, s.instanceId, email)
}

// Update updates user fields
func (s *UserService) Update(ctx context.Context, user *models.User) error {
	now := time.Now()
	user.UpdatedAt = now
	return s.db.WithContext(ctx).Save(user).Error
}

// UpdateLastSignIn updates user's last sign in timestamp
func (s *UserService) UpdateLastSignIn(ctx context.Context, userID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Update("last_sign_in_at", now).Error
}

// UpdateUsername updates user's username
func (s *UserService) UpdateUsername(ctx context.Context, userID uint, instanceId, username string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"username":   username,
			"updated_at": now,
		}).Error
}

// UpdateEmail updates user's email
func (s *UserService) UpdateEmail(ctx context.Context, userID uint, instanceId, email string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"email":      email,
			"updated_at": now,
		}).Error
}

// UpdatePhone updates user's phone
func (s *UserService) UpdatePhone(ctx context.Context, userID uint, instanceId, phone string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"phone":      phone,
			"updated_at": now,
		}).Error
}

// UpdatePassword updates user's password
func (s *UserService) UpdatePassword(ctx context.Context, userID uint, instanceId, hashedPassword string) error {
	now := time.Now()
	slog.Info("DEBUG: UpdatePassword called", "userID", userID, "instanceId", instanceId, "hashedPassword", hashedPassword[:10]+"...")

	result := s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"encrypted_password": hashedPassword,
			"updated_at":         now,
		})

	slog.Info("DEBUG: UpdatePassword result", "rowsAffected", result.RowsAffected, "error", result.Error)
	return result.Error
}

// ConfirmEmail marks user's email as confirmed
func (s *UserService) ConfirmEmail(ctx context.Context, userID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"email_confirmed_at": now,
			"confirmed_at":       now,
			"updated_at":         now,
		}).Error
}

// ConfirmPhone marks user's phone as confirmed
func (s *UserService) ConfirmPhone(ctx context.Context, userID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"phone_confirmed_at": now,
			"confirmed_at":       now,
			"updated_at":         now,
		}).Error
}

// SetBan bans user until specified time
func (s *UserService) SetBan(ctx context.Context, userID uint, instanceId string, until time.Time) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"banned_until": until,
			"updated_at":   now,
		}).Error
}

// RemoveBan removes user ban
func (s *UserService) RemoveBan(ctx context.Context, userID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Updates(map[string]any{
			"banned_until": nil,
			"updated_at":   now,
		}).Error
}

// Delete soft deletes user
func (s *UserService) Delete(ctx context.Context, userID uint, instanceId string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", userID, instanceId).
		Update("deleted_at", now).Error
}

// ExistsByUsername checks if user exists by username
func (s *UserService) ExistsByUsername(ctx context.Context, username, instanceId string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("username = ? AND instance_id = ? AND deleted_at IS NULL", username, instanceId).
		Count(&count).Error
	return count > 0, err
}

// ExistsByEmail checks if user exists by email
func (s *UserService) ExistsByEmail(ctx context.Context, email, instanceId string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("email = ? AND instance_id = ? AND deleted_at IS NULL", email, instanceId).
		Count(&count).Error
	return count > 0, err
}

// ExistsByPhone checks if user exists by phone
func (s *UserService) ExistsByPhone(ctx context.Context, phone, instanceId string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("phone = ? AND instance_id = ? AND deleted_at IS NULL", phone, instanceId).
		Count(&count).Error
	return count > 0, err
}

// GetWithIdentities retrieves user with their identities
func (s *UserService) GetWithIdentities(ctx context.Context, userID uint, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Preload("Identities").
		Where("id = ? AND instance_id = ?", userID, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetWithMFAFactors retrieves user with their MFA factors
func (s *UserService) GetWithMFAFactors(ctx context.Context, userID uint, instanceId string) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).Preload("MFAFactors").
		Where("id = ? AND instance_id = ?", userID, instanceId).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// List retrieves users with pagination
func (s *UserService) List(ctx context.Context, instanceId string, offset, limit int) ([]models.User, int64, error) {
	var users []models.User
	var total int64

	// Get total count
	err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("instance_id = ? AND deleted_at IS NULL", instanceId).
		Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// Get users with pagination
	err = s.db.WithContext(ctx).Where("instance_id = ? AND deleted_at IS NULL", instanceId).
		Order("updated_at DESC").Offset(offset).Limit(limit).Find(&users).Error
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// CountByInstance counts users in instance
func (s *UserService) CountByInstance(ctx context.Context, instanceId string) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&models.User{}).
		Where("instance_id = ? AND deleted_at IS NULL", instanceId).
		Count(&count).Error
	return count, err
}

type User struct {
	*models.User
	HashID string `json:"hashid"`

	// Direct dependencies
	passwordService *PasswordService `json:"-"`
	sessionService  *SessionService  `json:"-"`
	db              *gorm.DB         `json:"-"`
	instanceId      string           `json:"-"`
}

// GetModel Return underlying models.User
func (u *User) GetModel() *models.User {
	return u.User
}

func (u *User) GetDB() *gorm.DB {
	return u.db
}

func (u *User) GetInstanceId() string {
	return u.instanceId
}

// Session related methods - transferred from SessionService

// GetActiveSessions Get user's active sessions
func (u *User) GetActiveSessions(ctx context.Context) ([]*Session, error) {
	var sessions []models.Session
	err := u.db.WithContext(ctx).Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)",
		u.ID, u.instanceId, time.Now()).Order("updated_at DESC").Find(&sessions).Error
	if err != nil {
		return nil, err
	}

	// Convert to Session objects
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

// RevokeAllSessions Revoke all user sessions and refresh tokens (industry best practice)
func (u *User) RevokeAllSessions(ctx context.Context) error {
	now := GetDatabaseNow(u.db)

	// Start transaction to ensure atomicity
	tx := u.db.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. Set not_after for all active sessions
	if err := tx.Model(&models.Session{}).
		Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)",
			u.ID, u.instanceId, now).
		Updates(map[string]any{
			"not_after":  now,
			"updated_at": now,
		}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// 2. Revoke all refresh tokens for this user (Supabase best practice)
	if err := tx.Model(&models.RefreshToken{}).
		Where("user_id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"revoked":    true,
			"updated_at": now,
		}).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// RevokeAllSessionsExcept Revoke all user sessions except specified one
func (u *User) RevokeAllSessionsExcept(ctx context.Context, exceptSessionID uint) error {
	now := GetDatabaseNow(u.db)
	return u.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND instance_id = ? AND id != ? AND (not_after IS NULL OR not_after > ?)",
			u.ID, u.instanceId, exceptSessionID, now).
		Updates(map[string]any{
			"not_after":  now,
			"updated_at": now,
		}).Error
}

// CountActiveSessions Count user's active sessions
func (u *User) CountActiveSessions(ctx context.Context) (int64, error) {
	var count int64
	dbNow := GetDatabaseNow(u.db)
	err := u.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)",
			u.ID, u.instanceId, dbNow).
		Count(&count).Error
	return count, err
}

// GetSessionsWithRefreshTokens Get user sessions with refresh tokens
func (u *User) GetSessionsWithRefreshTokens(ctx context.Context) ([]models.Session, error) {
	var sessions []models.Session
	dbNow := GetDatabaseNow(u.db)
	err := u.db.WithContext(ctx).Preload("RefreshTokens").
		Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)",
			u.ID, u.instanceId, dbNow).Order("updated_at DESC").Find(&sessions).Error
	return sessions, err
}

// Admin Session related methods - transferred from AdminSessionService

func (u *User) ListSessions(ctx context.Context, page, pageSize int) ([]*Session, int64, error) {
	var sessions []models.Session
	var total int64

	// Get total count
	if err := u.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND instance_id = ?", u.ID, u.instanceId).
		Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get sessions with pagination
	offset := (page - 1) * pageSize
	if err := u.db.WithContext(ctx).Where("user_id = ? AND instance_id = ?", u.ID, u.instanceId).
		Order("updated_at DESC").Offset(offset).Limit(pageSize).Find(&sessions).Error; err != nil {
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

// Identity related methods - transferred from AdminIdentityService

// ListIdentities List user identity records
func (u *User) ListIdentities(ctx context.Context) ([]*UserIdentity, error) {
	var identities []models.Identity
	if err := u.db.WithContext(ctx).Where("user_id = ? AND instance_id = ?", u.ID, u.instanceId).
		Find(&identities).Error; err != nil {
		return nil, err
	}

	// Convert to UserIdentity
	identityObjects := make([]*UserIdentity, len(identities))
	for i, identity := range identities {
		identityObj, err := NewUserIdentity(&identity)
		if err != nil {
			return nil, err
		}
		identityObjects[i] = identityObj
	}

	return identityObjects, nil
}

// DeleteIdentity Delete user identity record
func (u *User) DeleteIdentity(ctx context.Context, identityID string) error {
	// Parse identityID to get real ID
	realIdentityID, err := GetUserIDFromHashID(identityID)
	if err != nil {
		return fmt.Errorf("invalid identity ID format: %w", err)
	}

	return u.db.WithContext(ctx).Where("id = ? AND user_id = ? AND instance_id = ?",
		realIdentityID, u.ID, u.instanceId).Delete(&models.Identity{}).Error
}

// Package level functions - user creation and query

func CreateUser(ctx context.Context, db *gorm.DB, instanceId string, opts *UserCreateOptions) (*User, error) {
	userService := NewUserServiceWithInstance(db, instanceId)
	return userService.CreateUser(ctx, opts)
}

// CreateUserWithSource creates a user with source information (for admin/internal use)
func CreateUserWithSource(ctx context.Context, db *gorm.DB, instanceId string, opts *UserCreateOptions, source UserCreatedSource, extraContext map[string]any, httpRequest *http.Request) (*User, error) {
	userService := NewUserServiceWithInstance(db, instanceId)
	return userService.CreateUserWithSource(ctx, opts, source, extraContext, httpRequest)
}

// GetUserByID Get user by ID
func GetUserByID(ctx context.Context, db *gorm.DB, instanceId string, id uint) (*User, error) {
	var userModel models.User
	err := db.WithContext(ctx).Preload("Identities").
		Where("id = ? AND instance_id = ?", id, instanceId).First(&userModel).Error
	if err != nil {
		return nil, err
	}

	passwordService := NewPasswordService(nil, getAppSecret(), getDefaultPasswordStrengthScore())
	return NewUserFromModel(&userModel, passwordService, NewSessionService(db), db, instanceId)
}

// GetUserByHashID Get user by HashID
func GetUserByHashID(ctx context.Context, db *gorm.DB, instanceId string, hashID string) (*User, error) {
	realUserID, err := GetUserIDFromHashID(hashID)
	if err != nil {
		return nil, err
	}
	return GetUserByID(ctx, db, instanceId, realUserID)
}

// GetUserByEmail Get user by email
func GetUserByEmail(ctx context.Context, db *gorm.DB, instanceId string, email string) (*User, error) {
	var userModel models.User
	err := db.WithContext(ctx).Preload("Identities").
		Where("email = ? AND instance_id = ?", email, instanceId).First(&userModel).Error
	if err != nil {
		return nil, err
	}

	passwordService := NewPasswordService(nil, getAppSecret(), getDefaultPasswordStrengthScore())
	return NewUserFromModel(&userModel, passwordService, NewSessionService(db), db, instanceId)
}

// GetUserByPhone Get user by phone
func GetUserByPhone(ctx context.Context, db *gorm.DB, instanceId string, phone string) (*User, error) {
	var userModel models.User
	err := db.WithContext(ctx).Where("phone = ? AND instance_id = ?", phone, instanceId).First(&userModel).Error
	if err != nil {
		return nil, err
	}

	passwordService := NewPasswordService(nil, getAppSecret(), getDefaultPasswordStrengthScore())
	return NewUserFromModel(&userModel, passwordService, NewSessionService(db), db, instanceId)
}

// GetUserByEmailOrPhone Get user by email or phone
func GetUserByEmailOrPhone(ctx context.Context, db *gorm.DB, instanceId string, emailOrPhone string) (*User, error) {
	var userModel models.User
	err := db.WithContext(ctx).Where("(email = ? OR phone = ?) AND instance_id = ?",
		emailOrPhone, emailOrPhone, instanceId).First(&userModel).Error
	if err != nil {
		return nil, err
	}

	passwordService := NewPasswordService(nil, getAppSecret(), getDefaultPasswordStrengthScore())
	return NewUserFromModel(&userModel, passwordService, NewSessionService(db), db, instanceId)
}

// ListUsers Get user list
func ListUsers(ctx context.Context, db *gorm.DB, instanceId string, offset, limit int, filters map[string]any) ([]*User, int64, error) {
	var userModels []models.User
	var total int64

	// Build query
	query := db.WithContext(ctx).Model(&models.User{}).Where("instance_id = ? AND deleted_at IS NULL", instanceId)

	// Apply filters
	if email, ok := filters["email"]; ok {
		query = query.Where("email LIKE ?", "%"+fmt.Sprintf("%v", email)+"%")
	}
	if phone, ok := filters["phone"]; ok {
		query = query.Where("phone LIKE ?", "%"+fmt.Sprintf("%v", phone)+"%")
	}
	if confirmed, ok := filters["email_confirmed"]; ok {
		if fmt.Sprintf("%v", confirmed) == "true" {
			query = query.Where("email_confirmed_at IS NOT NULL")
		} else {
			query = query.Where("email_confirmed_at IS NULL")
		}
	}
	if confirmed, ok := filters["phone_confirmed"]; ok {
		if fmt.Sprintf("%v", confirmed) == "true" {
			query = query.Where("phone_confirmed_at IS NOT NULL")
		} else {
			query = query.Where("phone_confirmed_at IS NULL")
		}
	}

	// Generic JSON metadata filters
	for key, value := range filters {
		if strings.HasPrefix(key, "app_metadata.") {
			path := strings.TrimPrefix(key, "app_metadata.")
			query = query.Where(datatypes.JSONQuery("raw_app_meta_data").Equals(value, path))
		} else if strings.HasPrefix(key, "user_metadata.") {
			path := strings.TrimPrefix(key, "user_metadata.")
			query = query.Where(datatypes.JSONQuery("raw_user_meta_data").Equals(value, path))
		}
	}

	// Get total count
	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// Get users with pagination
	err = query.Order("updated_at DESC").Offset(offset).Limit(limit).Find(&userModels).Error
	if err != nil {
		return nil, 0, err
	}

	// Convert to User objects
	users := make([]*User, len(userModels))
	passwordService := NewPasswordService(nil, getAppSecret(), getDefaultPasswordStrengthScore())
	for i, userModel := range userModels {
		user, err := NewUserFromModel(&userModel, passwordService, NewSessionService(db), db, instanceId)
		if err != nil {
			return nil, 0, err
		}
		users[i] = user
	}

	return users, total, nil
}

// UserExists Check if user exists
func UserExistsByEmail(ctx context.Context, db *gorm.DB, instanceId string, email string) (bool, error) {
	var count int64
	err := db.WithContext(ctx).Model(&models.User{}).
		Where("email = ? AND instance_id = ? AND deleted_at IS NULL", email, instanceId).
		Count(&count).Error
	return count > 0, err
}

func UserExistsByPhone(ctx context.Context, db *gorm.DB, instanceId string, phone string) (bool, error) {
	var count int64
	err := db.WithContext(ctx).Model(&models.User{}).
		Where("phone = ? AND instance_id = ? AND deleted_at IS NULL", phone, instanceId).
		Count(&count).Error
	return count > 0, err
}

// NewUserFromModel Create User object from model
func NewUserFromModel(userModel *models.User, passwordService *PasswordService, sessionService *SessionService, db *gorm.DB, instanceId string) (*User, error) {
	hashid, err := generateHashID(userModel.ID)
	if err != nil {
		return nil, err
	}

	return &User{
		User:            userModel,
		HashID:          hashid,
		passwordService: passwordService,
		sessionService:  sessionService,
		db:              db,
		instanceId:      instanceId,
	}, nil
}

// User status check methods
func (u *User) IsEmailConfirmed() bool {
	return u.EmailConfirmedAt != nil
}

func (u *User) IsPhoneConfirmed() bool {
	return u.PhoneConfirmedAt != nil
}

func (u *User) IsBanned() bool {
	return u.BannedUntil != nil && u.BannedUntil.After(time.Now())
}

func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

func (u *User) IsAnonymous() bool {
	return u.User.IsAnonymous
}

// User property getter methods
func (u *User) GetUsername() string {
	if u.Username == nil {
		return ""
	}
	return *u.Username
}

func (u *User) GetEmail() string {
	if u.Email == nil {
		return ""
	}
	return *u.Email
}

func (u *User) GetPhone() string {
	if u.Phone == nil {
		return ""
	}
	return *u.Phone
}

func (u *User) GetDisplayName() string {
	username := u.GetUsername()
	if username != "" {
		return username
	}
	email := u.GetEmail()
	if email != "" {
		return email
	}
	return u.GetPhone()
}

func (u *User) GetMetadata() map[string]any {
	if u.RawUserMetaData == nil {
		return make(map[string]any)
	}
	var metadata map[string]any
	if err := json.Unmarshal(*u.RawUserMetaData, &metadata); err != nil {
		return make(map[string]any)
	}
	return metadata
}

func (u *User) GetAppMetadata() map[string]any {
	if u.RawAppMetaData == nil {
		return make(map[string]any)
	}
	var metadata map[string]any
	if err := json.Unmarshal(*u.RawAppMetaData, &metadata); err != nil {
		return make(map[string]any)
	}
	return metadata
}

// User update methods
func (u *User) UpdateUsername(ctx context.Context, username string) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"username":   username,
			"updated_at": now,
		}).Error
	if err != nil {
		return err
	}
	u.Username = &username
	u.UpdatedAt = now
	return nil
}

func (u *User) UpdateEmail(ctx context.Context, email string) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"email":      email,
			"updated_at": now,
		}).Error
	if err != nil {
		return err
	}
	u.Email = &email
	u.UpdatedAt = now
	return nil
}

func (u *User) UpdatePhone(ctx context.Context, phone string) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"phone":      phone,
			"updated_at": now,
		}).Error
	if err != nil {
		return err
	}
	u.Phone = &phone
	u.UpdatedAt = now
	return nil
}

func (u *User) UpdatePassword(ctx context.Context, newPassword string) error {
	hashedPassword, err := u.passwordService.HashPassword(newPassword)
	if err != nil {
		return err
	}
	now := time.Now()
	err = u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"encrypted_password": hashedPassword,
			"updated_at":         now,
		}).Error
	if err != nil {
		return err
	}
	u.EncryptedPassword = &hashedPassword
	u.UpdatedAt = now
	return nil
}

func (u *User) UpdateMetadata(ctx context.Context, metadata map[string]any) error {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	rawMetadata := json.RawMessage(metadataJSON)
	err = u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"raw_user_meta_data": rawMetadata,
			"updated_at":         time.Now(),
		}).Error
	if err != nil {
		return err
	}
	u.RawUserMetaData = (*models.JSON)(&rawMetadata)
	u.UpdatedAt = time.Now()
	return nil
}

// UpdateAppMetadata updates user's app metadata
func (u *User) UpdateAppMetadata(ctx context.Context, metadata map[string]any) error {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	rawMetadata := json.RawMessage(metadataJSON)
	err = u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"raw_app_meta_data": rawMetadata,
			"updated_at":        time.Now(),
		}).Error
	if err != nil {
		return err
	}
	u.RawAppMetaData = (*models.JSON)(&rawMetadata)
	u.UpdatedAt = time.Now()
	return nil
}

// SetAppMetadata sets user's app metadata (creates or updates)
func (u *User) SetAppMetadata(ctx context.Context, metadata map[string]any) error {
	return u.UpdateAppMetadata(ctx, metadata)
}

func (u *User) ConfirmEmail(ctx context.Context) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"email_confirmed_at": now,
			"confirmed_at":       now,
			"updated_at":         now,
		}).Error
	if err != nil {
		return err
	}
	u.EmailConfirmedAt = &now
	u.ConfirmedAt = &now
	u.UpdatedAt = now
	return nil
}

func (u *User) ConfirmPhone(ctx context.Context) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"phone_confirmed_at": now,
			"confirmed_at":       now,
			"updated_at":         now,
		}).Error
	if err != nil {
		return err
	}
	u.PhoneConfirmedAt = &now
	u.ConfirmedAt = &now
	u.UpdatedAt = now
	return nil
}

func (u *User) SetBan(ctx context.Context, until time.Time) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"banned_until": until,
			"updated_at":   now,
		}).Error
	if err != nil {
		return err
	}
	u.BannedUntil = &until
	u.UpdatedAt = now
	return nil
}

func (u *User) RemoveBan(ctx context.Context) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Updates(map[string]any{
			"banned_until": nil,
			"updated_at":   now,
		}).Error
	if err != nil {
		return err
	}
	u.BannedUntil = nil
	u.UpdatedAt = now
	return nil
}

func (u *User) UpdateLastSignIn(ctx context.Context) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Update("last_sign_in_at", now).Error
	if err != nil {
		return err
	}
	u.LastSignInAt = &now
	return nil
}

// User authentication related methods
func (u *User) VerifyPassword(password string) (bool, error) {
	if u.EncryptedPassword == nil {
		return false, consts.INVALID_CREDENTIALS
	}
	return u.passwordService.VerifyPassword(password, *u.EncryptedPassword)
}

// Related data loading methods
func (u *User) LoadIdentities(ctx context.Context) error {
	err := u.db.WithContext(ctx).Preload("Identities").
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).First(u.User).Error
	return err
}

func (u *User) LoadMFAFactors(ctx context.Context) error {
	err := u.db.WithContext(ctx).Preload("MFAFactors").
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).First(u.User).Error
	return err
}

// MFA related methods

// EnrollMFAFactor Enroll MFA factor
func (u *User) EnrollMFAFactor(ctx context.Context, factorType types.FactorType, friendlyName string, secret string, phone string) (*models.MFAFactor, error) {
	factor := &models.MFAFactor{
		UserID:       u.ID,
		FriendlyName: &friendlyName,
		FactorType:   factorType,
		Status:       types.FactorStatusUnverified,
		Secret:       &secret,
		Phone:        &phone,
		InstanceId:   u.instanceId,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := u.db.WithContext(ctx).Create(factor).Error; err != nil {
		return nil, err
	}

	return factor, nil
}

// VerifyMFAFactor Verify and activate MFA factor
func (u *User) VerifyMFAFactor(ctx context.Context, factorID uint) error {
	now := time.Now()
	return u.db.WithContext(ctx).Model(&models.MFAFactor{}).
		Where("id = ? AND user_id = ? AND instance_id = ?", factorID, u.ID, u.instanceId).
		Updates(map[string]any{
			"status":     types.FactorStatusVerified,
			"updated_at": now,
		}).Error
}

// ListMFAFactors List user's MFA factors
func (u *User) ListMFAFactors(ctx context.Context) ([]models.MFAFactor, error) {
	var factors []models.MFAFactor
	err := u.db.WithContext(ctx).Where("user_id = ? AND instance_id = ?", u.ID, u.instanceId).
		Find(&factors).Error
	return factors, err
}

// GetMFAFactor Get specified MFA factor
func (u *User) GetMFAFactor(ctx context.Context, factorID uint) (*models.MFAFactor, error) {
	var factor models.MFAFactor
	err := u.db.WithContext(ctx).Where("id = ? AND user_id = ? AND instance_id = ?",
		factorID, u.ID, u.instanceId).First(&factor).Error
	if err != nil {
		return nil, err
	}
	return &factor, nil
}

// DeleteMFAFactor Delete MFA factor
func (u *User) DeleteMFAFactor(ctx context.Context, factorID uint) error {
	return u.db.WithContext(ctx).Where("id = ? AND user_id = ? AND instance_id = ?",
		factorID, u.ID, u.instanceId).Delete(&models.MFAFactor{}).Error
}

// CountVerifiedMFAFactors Count verified MFA factors
func (u *User) CountVerifiedMFAFactors(ctx context.Context) (int64, error) {
	var count int64
	err := u.db.WithContext(ctx).Model(&models.MFAFactor{}).
		Where("user_id = ? AND instance_id = ? AND status = ?",
			u.ID, u.instanceId, types.FactorStatusVerified).
		Count(&count).Error
	return count, err
}

// HasVerifiedMFAFactors Check if user has verified MFA factors
func (u *User) HasVerifiedMFAFactors(ctx context.Context) (bool, error) {
	count, err := u.CountVerifiedMFAFactors(ctx)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (u *User) LoadSessions(ctx context.Context) error {
	err := u.db.WithContext(ctx).Preload("Sessions").
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).First(u.User).Error
	return err
}

// Delete user (soft delete)
func (u *User) Delete(ctx context.Context) error {
	now := time.Now()
	err := u.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND instance_id = ?", u.ID, u.instanceId).
		Update("deleted_at", now).Error
	if err != nil {
		return err
	}
	u.DeletedAt = &now
	return nil
}

// Check if user can sign in
func (u *User) CanSignIn() bool {
	return !u.IsDeleted() && !u.IsBanned()
}

// GetUsersByHashIDs loads multiple users by their hash IDs across all instances
// This is a package-level convenience function for batch loading users without creating a UserService
//
// Parameters:
//   - ctx: context for the database query
//   - db: gorm database connection
//   - hashIDs: slice of user hash IDs to load
//
// Returns:
//   - map[string]*User: map of hashID -> User for efficient lookup
//   - error: any error during the query
func GetUsersByHashIDs(ctx context.Context, db *gorm.DB, hashIDs []string) (map[string]*User, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	if len(hashIDs) == 0 {
		return make(map[string]*User), nil
	}

	// 1. Decode all hashIDs to get numeric IDs
	userIDs := make([]uint, 0, len(hashIDs))
	hashIDToNumeric := make(map[uint]string)

	for _, hashID := range hashIDs {
		numericID, err := GetUserIDFromHashID(hashID)
		if err == nil {
			userIDs = append(userIDs, numericID)
			hashIDToNumeric[numericID] = hashID
		}
	}

	if len(userIDs) == 0 {
		return make(map[string]*User), nil
	}

	// 2. Batch query (not restricted by instance_id)
	var userModels []*models.User
	err := db.WithContext(ctx).Where("id IN ?", userIDs).Find(&userModels).Error
	if err != nil {
		return nil, err
	}

	// 3. Build result map
	result := make(map[string]*User, len(userModels))
	for _, userModel := range userModels {
		if hashID, ok := hashIDToNumeric[userModel.ID]; ok {
			result[hashID] = &User{
				User:       userModel,
				HashID:     hashID,
				db:         db,
				instanceId: userModel.InstanceId,
			}
		}
	}

	return result, nil
}

// executeBeforeUserCreatedMiddlewares 执行Before middlewares
func (s *UserService) executeBeforeUserCreatedMiddlewares(
	ctx context.Context,
	tx *gorm.DB,
	userModel *models.User,
	source UserCreatedSource,
	opts *UserCreateOptions,
	extraContext map[string]any,
	httpRequest *http.Request,
) error {
	// 获取AuthService实例
	if s.authService == nil {
		return nil // 如果没有AuthService，跳过middleware
	}

	authServiceImpl, ok := s.authService.(*AuthServiceImpl)
	if !ok {
		return nil
	}

	middlewares := authServiceImpl.GetBeforeUserCreatedMiddlewares()
	if len(middlewares) == 0 {
		return nil
	}

	// 创建Context（Before时User对象还未创建，所以user为nil）
	userCreatedCtx := &userCreatedContextImpl{
		Context:      ctx,
		authService:  s.authService,
		httpRequest:  httpRequest,
		user:         nil, // Before时User对象还未创建
		userModel:    userModel,
		source:       source,
		opts:         opts,
		extraContext: extraContext,
		isBeforeHook: true,
	}

	// Execute middleware chain with panic recovery
	return executeMiddlewareChainWithRecovery(
		len(middlewares),
		func(index int, next func() error) error {
			return middlewares[index](userCreatedCtx, next)
		},
		"BeforeUserCreatedUse",
	)
}

// executeAfterUserCreatedMiddlewares 执行After middlewares
func (s *UserService) executeAfterUserCreatedMiddlewares(
	ctx context.Context,
	tx *gorm.DB,
	user *User,
	source UserCreatedSource,
	extraContext map[string]any,
	httpRequest *http.Request,
) error {
	// 获取AuthService实例
	if s.authService == nil {
		return nil // 如果没有AuthService，跳过middleware
	}

	authServiceImpl, ok := s.authService.(*AuthServiceImpl)
	if !ok {
		return nil
	}

	middlewares := authServiceImpl.GetAfterUserCreatedMiddlewares()
	if len(middlewares) == 0 {
		return nil
	}

	// 创建Context（After时User对象已创建，ID已分配）
	userCreatedCtx := &userCreatedContextImpl{
		Context:      ctx,
		authService:  s.authService,
		httpRequest:  httpRequest,
		user:         user,
		userModel:    nil, // After时不需要userModel
		source:       source,
		opts:         nil, // After时不需要opts
		extraContext: extraContext,
		isBeforeHook: false,
	}

	// Execute middleware chain with panic recovery
	return executeMiddlewareChainWithRecovery(
		len(middlewares),
		func(index int, next func() error) error {
			return middlewares[index](userCreatedCtx, next)
		},
		"AfterUserCreatedUse",
	)
}
