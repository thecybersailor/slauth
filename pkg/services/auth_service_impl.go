package services

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

// SessionStats represents session statistics
type SessionStats struct {
	TotalSessions   int64 `json:"total_sessions"`
	ActiveSessions  int64 `json:"active_sessions"`
	ExpiredSessions int64 `json:"expired_sessions"`
}

// AuthServiceImpl implements authentication business logic
type AuthServiceImpl struct {
	db              *gorm.DB
	configLoader    *ConfigLoader
	jwtService      *JWTService
	passwordService *PasswordService
	otpService      *OTPService
	validator       *ValidatorService
	instanceId      string

	// External providers
	captchaProvider          types.CaptchaProvider
	mfaProviders             map[string]types.MFAProvider
	identityProviders        map[string]types.IdentityProvider
	smsProvider              types.SMSProvider
	emailProvider            types.EmailProvider
	messageTemplateResolvers []types.MessageTemplateResolver

	// Service layers
	userService         *UserService
	sessionService      *SessionService
	refreshTokenService *RefreshTokenService
	otTokenService      *OneTimeTokenService
	rateLimitService    *RateLimitService

	// Admin service layers
	adminSessionService  *AdminSessionService
	adminIdentityService *AdminIdentityService
	adminSystemService   *AdminSystemService

	// Route handlers
	authRouteHandler  RouteHandler
	adminRouteHandler RouteHandler

	// Flow middleware storage
	signupMiddlewares   []func(ctx SignupContext, next func() error) error
	signinMiddlewares   []func(ctx SigninContext, next func() error) error
	passwordMiddlewares []func(ctx PasswordContext, next func() error) error
	otpMiddlewares      []func(ctx OTPContext, next func() error) error
}

// NewAuthServiceImpl creates a new authentication service with global secrets
// This is an internal implementation, use auth.NewService() instead
func NewAuthServiceImpl(db *gorm.DB, instanceId, globalJWTSecret, globalAppSecret string) *AuthServiceImpl {
	// Create config loader
	configLoader := NewConfigLoader(db, instanceId, globalJWTSecret, globalAppSecret)

	// Load config for the first time
	cfg := configLoader.GetConfig()

	// Create service instance first (without jwtService)
	s := &AuthServiceImpl{
		db:           db,
		configLoader: configLoader,
		instanceId:   instanceId,
	}

	// Now create jwtService with closure that references configLoader
	jwtService := NewJWTService(
		cfg.JWTSecret,
		func() time.Duration {
			return time.Duration(configLoader.GetConfig().SessionConfig.AccessTokenTTL) * time.Second
		},
		func() time.Duration {
			return time.Duration(configLoader.GetConfig().SessionConfig.RefreshTokenTTL) * time.Second
		},
		cfg.AuthServiceBaseUrl,
	)

	// Initialize HashIDService and set as global instance
	hashIDService := NewHashIDService(cfg)
	SetGlobalHashIDService(hashIDService)

	userService := NewUserServiceWithInstance(db, instanceId)
	sessionService := NewSessionService(db)
	passwordService := NewPasswordService(nil, cfg.AppSecret, cfg.SecurityConfig.PasswordStrengthConfig.MinScore)

	// Set all fields
	s.jwtService = jwtService
	s.passwordService = passwordService
	s.otpService = NewOTPService(cfg.AuthServiceBaseUrl)
	s.validator = NewValidatorService()
	s.userService = userService
	s.sessionService = sessionService
	s.refreshTokenService = NewRefreshTokenService(db)
	s.otTokenService = NewOneTimeTokenService(db)
	s.rateLimitService = NewRateLimitService(cfg.AppSecret)

	// Initialize admin service layers
	s.adminSessionService = NewAdminSessionService(db, sessionService)
	s.adminIdentityService = NewAdminIdentityService(db)
	s.adminSystemService = NewAdminSystemService(db, userService, NewPasswordService(nil, cfg.AppSecret, cfg.SecurityConfig.PasswordStrengthConfig.MinScore), instanceId)

	// Initialize middleware slices
	s.signupMiddlewares = make([]func(ctx SignupContext, next func() error) error, 0)
	s.signinMiddlewares = make([]func(ctx SigninContext, next func() error) error, 0)
	s.passwordMiddlewares = make([]func(ctx PasswordContext, next func() error) error, 0)
	s.otpMiddlewares = []func(ctx OTPContext, next func() error) error{
		func(ctx OTPContext, next func() error) error {
			return checkEmailRateLimitWrapper(ctx, next)
		},
		func(ctx OTPContext, next func() error) error {
			return checkSMSRateLimitWrapper(ctx, next)
		},
	}

	// Initialize builtin template resolver as fallback
	s.messageTemplateResolvers = []types.MessageTemplateResolver{
		NewBuiltinTemplateResolver(),
	}

	return s
}

// NewAuthServiceImplWithPasswordService creates a new authentication service with a custom password service
// This allows external projects to inject custom password encoding implementations
func NewAuthServiceImplWithPasswordService(db *gorm.DB, instanceId, globalJWTSecret, globalAppSecret string, passwordService *PasswordService) *AuthServiceImpl {
	// Create config loader
	configLoader := NewConfigLoader(db, instanceId, globalJWTSecret, globalAppSecret)

	// Load config for the first time
	cfg := configLoader.GetConfig()

	// Create service instance first (without jwtService)
	s := &AuthServiceImpl{
		db:           db,
		configLoader: configLoader,
		instanceId:   instanceId,
	}

	// Now create jwtService with closure that references configLoader
	jwtService := NewJWTService(
		cfg.JWTSecret,
		func() time.Duration {
			return time.Duration(configLoader.GetConfig().SessionConfig.AccessTokenTTL) * time.Second
		},
		func() time.Duration {
			return time.Duration(configLoader.GetConfig().SessionConfig.RefreshTokenTTL) * time.Second
		},
		cfg.AuthServiceBaseUrl,
	)

	// Initialize HashIDService and set as global instance
	hashIDService := NewHashIDService(cfg)
	SetGlobalHashIDService(hashIDService)

	userService := NewUserServiceWithInstance(db, instanceId)
	sessionService := NewSessionService(db)

	// Set all fields
	s.jwtService = jwtService
	s.passwordService = passwordService // Use the provided password service
	s.otpService = NewOTPService(cfg.AuthServiceBaseUrl)
	s.validator = NewValidatorService()
	s.userService = userService
	s.sessionService = sessionService
	s.refreshTokenService = NewRefreshTokenService(db)
	s.otTokenService = NewOneTimeTokenService(db)
	s.rateLimitService = NewRateLimitService(cfg.AppSecret)

	// Initialize admin service layers
	s.adminSessionService = NewAdminSessionService(db, sessionService)
	s.adminIdentityService = NewAdminIdentityService(db)
	s.adminSystemService = NewAdminSystemService(db, userService, passwordService, instanceId)

	// Initialize middleware slices
	s.signupMiddlewares = make([]func(ctx SignupContext, next func() error) error, 0)
	s.signinMiddlewares = make([]func(ctx SigninContext, next func() error) error, 0)
	s.passwordMiddlewares = make([]func(ctx PasswordContext, next func() error) error, 0)
	s.otpMiddlewares = []func(ctx OTPContext, next func() error) error{
		func(ctx OTPContext, next func() error) error {
			return checkEmailRateLimitWrapper(ctx, next)
		},
		func(ctx OTPContext, next func() error) error {
			return checkSMSRateLimitWrapper(ctx, next)
		},
	}

	// Initialize builtin template resolver as fallback
	s.messageTemplateResolvers = []types.MessageTemplateResolver{
		NewBuiltinTemplateResolver(),
	}

	return s
}

// AuthenticateUser authenticates user with email/phone and password
func (s *AuthServiceImpl) AuthenticateUser(ctx context.Context, emailOrPhone, password string) (*User, error) {
	slog.Info("AuthenticateUser called",
		"emailOrPhone", emailOrPhone,
		"hasPassword", password != "",
		"instanceId", s.instanceId,
	)

	if emailOrPhone == "" || password == "" {
		slog.Error("Missing email/phone or password")
		return nil, consts.VALIDATION_FAILED
	}

	// Find user
	var user models.User
	query := s.db.Where("instance_id = ?", s.instanceId)

	// Try email first, then phone
	if err := s.validator.ValidateEmail(emailOrPhone); err == nil {
		emailOrPhone = s.validator.SanitizeEmail(emailOrPhone)
		query = query.Where("email = ?", emailOrPhone)
		slog.Info("Searching user by email", "email", emailOrPhone)
	} else {
		phoneOrPhone := s.validator.SanitizePhone(emailOrPhone)
		query = query.Where("phone = ?", phoneOrPhone)
		slog.Info("Searching user by phone", "phone", phoneOrPhone)
	}

	if err := query.First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			slog.Error("User not found in database", "emailOrPhone", emailOrPhone)
			return nil, consts.INVALID_CREDENTIALS
		}
		slog.Error("Database error during user lookup", "error", err)
		return nil, err
	}

	slog.Info("User found in database",
		"userID", user.ID,
		"email", user.Email,
		"hasEncryptedPassword", user.EncryptedPassword != nil,
	)

	// Check if user is banned
	if user.BannedUntil != nil && user.BannedUntil.After(time.Now()) {
		return nil, consts.USER_BANNED
	}

	// Verify password
	if user.EncryptedPassword == nil {
		slog.Error("User has no encrypted password", "userID", user.ID)
		return nil, consts.INVALID_CREDENTIALS
	}

	slog.Info("Verifying password", "userID", user.ID)
	valid, err := s.passwordService.VerifyPassword(password, *user.EncryptedPassword)
	if err != nil {
		slog.Error("Password verification error", "userID", user.ID, "error", err)
		return nil, err
	}

	if !valid {
		slog.Error("Password verification failed", "userID", user.ID)
		return nil, consts.INVALID_CREDENTIALS
	}

	slog.Info("Password verification successful", "userID", user.ID)

	// Update last sign in
	now := time.Now()
	user.LastSignInAt = &now
	s.db.Save(&user)

	slog.Info("Authentication successful", "userID", user.ID, "email", user.Email)

	// Wrap as User
	userObj, err := NewUserFromModel(&user, s.passwordService, s.sessionService, s.db, s.instanceId)
	if err != nil {
		slog.Error("Failed to create user object", "error", err, "userID", user.ID)
		return nil, consts.UNEXPECTED_FAILURE
	}

	return userObj, nil
}

// CreateSession creates a new session for user
func (s *AuthServiceImpl) CreateSession(ctx context.Context, user *User, aal types.AALLevel, amr []string, userAgent, ip string) (*Session, string, string, int64, error) {
	// Check if single session per user is enforced
	config := s.GetConfig()
	if config.SessionConfig.EnforceSingleSessionPerUser {
		// Terminate all existing sessions for this user
		s.db.Where("user_id = ? AND instance_id = ?", user.ID, s.instanceId).Delete(&models.Session{})
		// Revoke all existing refresh tokens for this user
		s.db.Model(&models.RefreshToken{}).
			Where("user_id = ? AND instance_id = ?", user.ID, s.instanceId).
			Update("revoked", true)
	}

	// Create session record
	now := time.Now()
	session := &models.Session{
		UserID:      user.ID,
		InstanceId:  s.instanceId,
		AAL:         &aal,
		CreatedAt:   now,
		UpdatedAt:   now,
		RefreshedAt: &now,
		UserAgent:   &userAgent,
		IP:          &ip,
	}

	// Set session expiration if time-box is configured
	if config.SessionConfig.TimeBoxUserSessions > 0 {
		notAfter := now.Add(time.Duration(config.SessionConfig.TimeBoxUserSessions) * time.Second)
		session.NotAfter = &notAfter
	}

	if err := s.db.Create(session).Error; err != nil {
		return nil, "", "", 0, err
	}

	// SQLite auto increment fix: refresh the session to get the correct ID
	if session.ID == 0 {
		if err := s.db.First(session, "user_id = ? AND instance_id = ? AND created_at = ?",
			user.ID, s.instanceId, session.CreatedAt).Error; err != nil {
			return nil, "", "", 0, err
		}
	}

	// Debug: Check if session.ID was set correctly
	slog.Info("Session created", "sessionID", session.ID, "userID", user.ID, "instanceId", s.instanceId)

	// Parse user metadata
	var userMeta, appMeta map[string]any
	if user.RawUserMetaData != nil {
		if err := json.Unmarshal(*user.RawUserMetaData, &userMeta); err != nil {
			return nil, "", "", 0, err
		}
	}
	// appMeta is temporarily empty because models.User doesn't have RawAppMetaData field

	// Generate access token
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	phone := ""
	if user.Phone != nil {
		phone = *user.Phone
	}

	accessToken, expiresAt, err := s.jwtService.GenerateAccessTokenWithExpiry(
		user.HashID, s.instanceId, email, phone, "authenticated",
		aal, amr, session.ID, userMeta, appMeta,
	)
	if err != nil {
		return nil, "", "", 0, err
	}

	// Generate refresh token
	refreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		return nil, "", "", 0, err
	}

	// Store refresh token
	refreshTokenRecord := &models.RefreshToken{
		Token:      refreshToken,
		UserID:     user.ID,
		SessionID:  session.ID,
		InstanceId: s.instanceId,
		Revoked:    false,
	}

	if err := s.db.Create(refreshTokenRecord).Error; err != nil {
		return nil, "", "", 0, err
	}

	// Wrap as Session
	sessionObj, err := NewSession(session)
	if err != nil {
		return nil, "", "", 0, consts.UNEXPECTED_FAILURE
	}

	return sessionObj, accessToken, refreshToken, expiresAt, nil
}

// RefreshSession refreshes an existing session with new tokens (reuses session per best practice)
func (s *AuthServiceImpl) RefreshSession(ctx context.Context, user *User, sessionID uint, aal types.AALLevel, amr []string, userAgent, ip string) (*Session, string, string, int64, error) {
	// Get existing session
	var session models.Session
	if err := s.db.First(&session, sessionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", "", 0, consts.SESSION_NOT_FOUND
		}
		return nil, "", "", 0, err
	}

	// Check if session has expired (time-box) and update session refresh time
	now := GetDatabaseNow(s.db)
	if session.NotAfter != nil && (session.NotAfter.Before(now) || session.NotAfter.Equal(now)) {
		return nil, "", "", 0, consts.SESSION_EXPIRED
	}

	// Update session refresh time and metadata
	session.RefreshedAt = &now
	session.UpdatedAt = now
	session.AAL = &aal
	session.UserAgent = &userAgent
	session.IP = &ip

	if err := s.db.Save(&session).Error; err != nil {
		return nil, "", "", 0, err
	}

	// Parse user metadata
	var userMeta, appMeta map[string]any
	if user.RawUserMetaData != nil {
		if err := json.Unmarshal(*user.RawUserMetaData, &userMeta); err != nil {
			return nil, "", "", 0, err
		}
	}

	// Generate new access token
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	phone := ""
	if user.Phone != nil {
		phone = *user.Phone
	}

	accessToken, expiresAt, err := s.jwtService.GenerateAccessTokenWithExpiry(
		user.HashID, s.instanceId, email, phone, "authenticated",
		aal, amr, session.ID, userMeta, appMeta,
	)
	if err != nil {
		return nil, "", "", 0, err
	}

	// Generate new refresh token
	refreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		return nil, "", "", 0, err
	}

	// Store new refresh token
	refreshTokenRecord := &models.RefreshToken{
		Token:      refreshToken,
		UserID:     user.ID,
		SessionID:  session.ID,
		InstanceId: s.instanceId,
		Revoked:    false,
	}

	if err := s.db.Create(refreshTokenRecord).Error; err != nil {
		return nil, "", "", 0, err
	}

	// Wrap as Session
	sessionObj, err := NewSession(&session)
	if err != nil {
		return nil, "", "", 0, consts.UNEXPECTED_FAILURE
	}

	return sessionObj, accessToken, refreshToken, expiresAt, nil
}

// ValidateRefreshToken validates and returns refresh token info
func (s *AuthServiceImpl) ValidateRefreshToken(ctx context.Context, tokenString string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := s.db.WithContext(ctx).Preload("Session").Where("token = ? AND instance_id = ? AND (revoked IS NULL OR revoked = false)",
		tokenString, s.instanceId).First(&token).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, consts.REFRESH_TOKEN_NOT_FOUND
		}
		return nil, err
	}

	// Check if associated session is revoked
	if token.Session != nil && token.Session.NotAfter != nil {
		dbNow := GetDatabaseNow(s.db)
		if token.Session.NotAfter.Before(dbNow) || token.Session.NotAfter.Equal(dbNow) {
			return nil, consts.SESSION_EXPIRED
		}
	}

	return &token, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *AuthServiceImpl) RevokeRefreshToken(ctx context.Context, tokenString string) error {
	result := s.db.Model(&models.RefreshToken{}).
		Where("token = ? AND instance_id = ?", tokenString, s.instanceId).
		Update("revoked", true)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return consts.REFRESH_TOKEN_NOT_FOUND
	}

	return nil
}

// ===== OAuth Flow State Management =====

// CreateFlowState creates a new OAuth flow state record
func (s *AuthServiceImpl) CreateFlowState(ctx context.Context, flowState *models.FlowState) error {
	return s.db.WithContext(ctx).Create(flowState).Error
}

// GetFlowStateByID retrieves flow state by ID
func (s *AuthServiceImpl) GetFlowStateByID(ctx context.Context, id uint) (*models.FlowState, error) {
	var flowState models.FlowState
	err := s.db.WithContext(ctx).Where("id = ? AND instance_id = ?", id, s.instanceId).First(&flowState).Error
	if err != nil {
		return nil, err
	}
	return &flowState, nil
}

// UpdateFlowState updates an existing flow state record
func (s *AuthServiceImpl) UpdateFlowState(ctx context.Context, flowState *models.FlowState) error {
	return s.db.WithContext(ctx).Save(flowState).Error
}

// DeleteFlowState deletes a flow state record
func (s *AuthServiceImpl) DeleteFlowState(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Delete(&models.FlowState{}, id).Error
}

// ValidateJWT validates a JWT token and returns user claims
func (s *AuthServiceImpl) ValidateJWT(token string) (map[string]any, error) {
	slog.Info("ValidateJWT: Starting token validation", "tokenLength", len(token))

	// Use JWT service to validate token
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		slog.Warn("ValidateJWT: JWT token validation failed", "error", err.Error())
		return nil, err
	}

	slog.Info("ValidateJWT: JWT token validation successful", "sessionID", claims.SessionID, "userID", claims.UserID)

	// Check if session is still valid (not revoked)
	// Get session from database to check if it's revoked
	var session models.Session
	err = s.db.Where("id = ? AND instance_id = ?", claims.SessionID, claims.InstanceId).First(&session).Error
	if err != nil {
		return nil, consts.SESSION_NOT_FOUND
	}

	// Check if session has expired (time-box)
	if session.NotAfter != nil {
		dbNow := GetDatabaseNow(s.db)
		if session.NotAfter.Before(dbNow) || session.NotAfter.Equal(dbNow) {
			return nil, consts.SESSION_EXPIRED
		}
	}

	// Check for inactivity timeout using database time difference calculation
	config := s.GetConfig()
	if config.SessionConfig.InactivityTimeout > 0 && session.RefreshedAt != nil {
		timeout := time.Duration(config.SessionConfig.InactivityTimeout) * time.Second

		inactiveSeconds := CalculateTimeDifference(s.db, *session.RefreshedAt)
		inactiveTime := time.Duration(inactiveSeconds) * time.Second

		slog.Info("ValidateJWT: Checking inactivity timeout",
			"refreshedAt", session.RefreshedAt,
			"inactiveSeconds", inactiveSeconds,
			"inactiveTime", inactiveTime,
			"timeout", timeout)
		if inactiveTime >= timeout {
			slog.Info("ValidateJWT: Session expired due to inactivity",
				"inactiveTime", inactiveTime,
				"timeout", timeout)
			return nil, consts.SESSION_EXPIRED
		}
	}

	// AAL timeout check is now automatically handled by Session model's AfterFind hook
	// Here we directly use the current AAL level read from database (may have been auto-downgraded)
	currentAAL := session.AAL

	// Use the current AAL from session (which may have been downgraded)
	aalValue := types.AALLevel1 // default
	if currentAAL != nil {
		aalValue = *currentAAL
	}

	// Extract user information from claims
	userClaims := map[string]any{
		"user_id":     claims.UserID, // Now stores hashid
		"instance_id": claims.InstanceId,
		"email":       claims.Email,
		"role":        claims.Role,
		"aal":         aalValue, // Use current AAL from session
		"amr":         claims.AMR,
		"session_id":  claims.SessionID,
		"sub":         claims.Subject,
	}

	return userClaims, nil
}

// External provider management
func (s *AuthServiceImpl) SetCaptchaProvider(provider types.CaptchaProvider) AuthService {
	s.captchaProvider = provider
	return s
}

func (s *AuthServiceImpl) AddIdentityProvider(provider types.IdentityProvider) AuthService {
	if s.identityProviders == nil {
		s.identityProviders = make(map[string]types.IdentityProvider)
	}
	s.identityProviders[provider.GetName()] = provider
	return s
}

func (s *AuthServiceImpl) GetIdentityProvider(name string) (types.IdentityProvider, bool) {
	if s.identityProviders == nil {
		return nil, false
	}
	provider, exists := s.identityProviders[name]
	return provider, exists
}

func (s *AuthServiceImpl) AddMFAProvider(provider types.MFAProvider) AuthService {
	if s.mfaProviders == nil {
		s.mfaProviders = make(map[string]types.MFAProvider)
	}
	s.mfaProviders[provider.GetName()] = provider
	return s
}

func (s *AuthServiceImpl) SetSMSProvider(provider types.SMSProvider) AuthService {
	s.smsProvider = provider
	return s
}

func (s *AuthServiceImpl) SetEmailProvider(provider types.EmailProvider) AuthService {
	s.emailProvider = provider
	return s
}

func (s *AuthServiceImpl) GetEmailProvider() types.EmailProvider {
	return s.emailProvider
}

func (s *AuthServiceImpl) GetSMSProvider() types.SMSProvider {
	return s.smsProvider
}

func (s *AuthServiceImpl) RegisterMessageTemplateResolver(resolver types.MessageTemplateResolver) AuthService {
	// Add new resolver to the front of the list, keeping built-in resolver as fallback
	s.messageTemplateResolvers = append([]types.MessageTemplateResolver{resolver}, s.messageTemplateResolvers...)
	return s
}

// GetMessageTemplate finds the first valid template resolver
func (s *AuthServiceImpl) GetMessageTemplate(instanceId, messageType, templateName string) (types.MessageTemplate, bool) {
	for _, resolver := range s.messageTemplateResolvers {
		if templateBytes, found := resolver.GetTemplate(instanceId, messageType, templateName); found {
			// Create internal template implementation
			template := &InternalMessageTemplate{
				templateBytes: templateBytes,
				messageType:   messageType,
			}
			return template, true
		}
	}
	return nil, false
}

// GenerateOTPCode generates a new OTP code
func (s *AuthServiceImpl) GenerateOTPCode(ctx OTPContext) (string, error) {
	return s.otpService.GenerateCode(ctx)
}

// GetOTPService returns the OTP service
func (s *AuthServiceImpl) GetOTPService() *OTPService {
	return s.otpService
}

// GetDB returns the database connection
func (s *AuthServiceImpl) GetDB() *gorm.DB {
	return s.db
}

func (s *AuthServiceImpl) GetInstanceId() string {
	return s.instanceId
}

func (s *AuthServiceImpl) GetConfig() *config.AuthServiceConfig {
	return s.configLoader.GetConfig()
}

func (s *AuthServiceImpl) SaveConfig(cfg *config.AuthServiceConfig) error {
	return s.configLoader.SaveConfig(cfg)
}

// GetOneTimeTokenService returns the one-time token service
func (s *AuthServiceImpl) GetOneTimeTokenService() *OneTimeTokenService {
	return s.otTokenService
}

// GetRateLimitService returns the rate limit service
func (s *AuthServiceImpl) GetRateLimitService() *RateLimitService {
	return s.rateLimitService
}

// GetConfigLoader returns the config loader
func (s *AuthServiceImpl) GetConfigLoader() *ConfigLoader {
	return s.configLoader
}

// GetUserService returns the user service
func (s *AuthServiceImpl) GetUserService() *UserService {
	return s.userService
}

// GetAdminSessionService returns the admin session service
func (s *AuthServiceImpl) GetAdminSessionService() *AdminSessionService {
	return s.adminSessionService
}

// GetAdminIdentityService returns the admin identity service
func (s *AuthServiceImpl) GetAdminIdentityService() *AdminIdentityService {
	return s.adminIdentityService
}

// GetAdminSystemService returns the admin system service
func (s *AuthServiceImpl) GetAdminSystemService() *AdminSystemService {
	return s.adminSystemService
}

// SetRouteHandler sets the route handler
func (s *AuthServiceImpl) SetRouteHandler(handler RouteHandler) AuthService {
	s.authRouteHandler = handler
	return s
}

// SetAdminRouteHandler sets the admin route handler
func (s *AuthServiceImpl) SetAdminRouteHandler(handler RouteHandler) AuthService {
	s.adminRouteHandler = handler
	return s
}

// HandleAuthRequest handles authentication-related public routes
func (s *AuthServiceImpl) HandleAuthRequest(router gin.IRouter) AuthService {
	// Set instance middleware
	router.Use(s.instanceMiddleware())

	// Call the configured route handler
	if s.authRouteHandler != nil {
		s.authRouteHandler.SetAuthService(s)
		s.authRouteHandler.RegisterRoutes(router)
	}
	return s
}

// HandleAdminRequest handles admin-related routes
func (s *AuthServiceImpl) HandleAdminRequest(router gin.IRouter) AuthService {
	// Set instance middleware
	router.Use(s.instanceMiddleware())

	// Call the configured admin route handler
	if s.adminRouteHandler != nil {
		s.adminRouteHandler.SetAuthService(s)
		s.adminRouteHandler.RegisterRoutes(router)
	}
	return s
}

func (s *AuthServiceImpl) instanceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx := &AuthContext{
			InstanceId:  s.instanceId,
			AuthService: s,
		}
		SetAuthContext(c, authCtx)
		c.Next()
	}
}

// RequestValidator returns JWT validation middleware
func (s *AuthServiceImpl) RequestValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		pinCtx := pin.Context{Context: c}

		// Set instance context
		authCtx := &AuthContext{
			InstanceId:  s.instanceId,
			AuthService: s,
		}
		SetAuthContext(c, authCtx)

		// Extract JWT token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			_ = pinCtx.RenderError(consts.NO_AUTHORIZATION)
			c.Abort()
			return
		}

		var token string
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}

		if token == "" {
			_ = pinCtx.RenderError(consts.BAD_JWT)
			c.Abort()
			return
		}

		// Validate JWT
		claims, err := s.ValidateJWT(token)
		if err != nil {
			// Return the actual error from ValidateJWT (e.g., SESSION_EXPIRED, SESSION_NOT_FOUND)
			_ = pinCtx.RenderError(err)
			c.Abort()
			return
		}

		authCtx.JWTToken = token
		authCtx.UserClaims = claims

		// Load user information
		userID, ok := claims["user_id"].(string)
		if !ok {
			_ = pinCtx.RenderError(consts.BAD_JWT)
			c.Abort()
			return
		}

		user, err := s.GetUserService().GetByHashID(c.Request.Context(), userID)
		if err != nil {
			_ = pinCtx.RenderError(consts.USER_NOT_FOUND)
			c.Abort()
			return
		}
		authCtx.User = user.User

		c.Next()
	}
}

// GetCurrentUser retrieves the current authenticated user from gin context
func (s *AuthServiceImpl) GetCurrentUser(c *gin.Context) (*User, error) {
	authCtx := GetAuthContext(c, s.instanceId)
	if authCtx.User == nil {
		return nil, consts.NO_AUTHORIZATION
	}
	return NewUserFromModel(authCtx.User, s.passwordService, s.sessionService, s.db, s.instanceId)
}

// InternalMessageTemplate internal template implementation, unified rendering logic
type InternalMessageTemplate struct {
	templateBytes []byte
	messageType   string
	renderService *MessageRenderService
}

// Render renders template and returns result
func (t *InternalMessageTemplate) Render(ctx context.Context, data map[string]interface{}) (types.MessageRenderResult, error) {
	if t.renderService == nil {
		t.renderService = NewMessageRenderService()
	}

	// Use render service to parse and render template
	templateInfo, err := t.renderService.ParseTemplateBytes(t.templateBytes)
	if err != nil {
		return nil, err
	}

	// Render template
	subject, content, err := t.renderService.RenderTemplate(templateInfo, data)
	if err != nil {
		return nil, err
	}

	result := &types.FileTemplateResult{
		Type:    t.messageType,
		Subject: &subject,
		Body:    content,
	}

	return result, nil
}

// SignupUse adds signup flow middleware
func (s *AuthServiceImpl) SignupUse(middleware func(ctx SignupContext, next func() error) error) AuthService {
	s.signupMiddlewares = append(s.signupMiddlewares, middleware)
	return s
}

// SigninUse adds signin flow middleware
func (s *AuthServiceImpl) SigninUse(middleware func(ctx SigninContext, next func() error) error) AuthService {
	s.signinMiddlewares = append(s.signinMiddlewares, middleware)
	return s
}

// PasswordUse adds password reset flow middleware
func (s *AuthServiceImpl) PasswordUse(middleware func(ctx PasswordContext, next func() error) error) AuthService {
	s.passwordMiddlewares = append(s.passwordMiddlewares, middleware)
	return s
}

// OTPUse adds OTP flow middleware
func (s *AuthServiceImpl) OTPUse(middleware func(ctx OTPContext, next func() error) error) AuthService {
	s.otpMiddlewares = append(s.otpMiddlewares, middleware)
	return s
}

// GetSignupMiddlewares gets signup flow middleware
func (s *AuthServiceImpl) GetSignupMiddlewares() []func(ctx SignupContext, next func() error) error {
	return s.signupMiddlewares
}

// GetSigninMiddlewares gets signin flow middleware
func (s *AuthServiceImpl) GetSigninMiddlewares() []func(ctx SigninContext, next func() error) error {
	return s.signinMiddlewares
}

// GetPasswordMiddlewares gets password reset flow middleware
func (s *AuthServiceImpl) GetPasswordMiddlewares() []func(ctx PasswordContext, next func() error) error {
	return s.passwordMiddlewares
}

// GetOTPMiddlewares gets OTP flow middleware
func (s *AuthServiceImpl) GetOTPMiddlewares() []func(ctx OTPContext, next func() error) error {
	return s.otpMiddlewares
}

func (s *AuthServiceImpl) GetMFAProvider(name string) (types.MFAProvider, bool) {
	if _, ok := s.mfaProviders[name]; !ok {
		return nil, false
	}
	return s.mfaProviders[name], true
}

func checkEmailRateLimitWrapper(ctx OTPContext, next func() error) error {
	req := ctx.Request()
	if req.Email == "" {
		return next()
	}

	authService := ctx.Service()
	authServiceImpl, ok := authService.(*AuthServiceImpl)
	if !ok {
		return next()
	}

	config := authServiceImpl.GetConfigLoader().GetConfig()
	rateLimitService := authServiceImpl.GetRateLimitService()

	// Use email as userKey for email rate limit
	allowed, err := rateLimitService.CheckAndRecordRequest(
		ctx,
		req.Email,
		"email_send",
		authService.GetInstanceId(),
		config.RatelimitConfig.EmailRateLimit,
		config,
	)

	if err != nil {
		return err
	}

	if !allowed {
		return consts.OVER_EMAIL_SEND_RATE_LIMIT
	}

	return next()
}

func checkSMSRateLimitWrapper(ctx OTPContext, next func() error) error {
	req := ctx.Request()
	if req.Phone == "" {
		return next()
	}

	authService := ctx.Service()
	authServiceImpl, ok := authService.(*AuthServiceImpl)
	if !ok {
		return next()
	}

	config := authServiceImpl.GetConfigLoader().GetConfig()
	rateLimitService := authServiceImpl.GetRateLimitService()

	// Use phone as userKey for SMS rate limit
	allowed, err := rateLimitService.CheckAndRecordRequest(
		ctx,
		req.Phone,
		"sms_send",
		authService.GetInstanceId(),
		config.RatelimitConfig.SMSRateLimit,
		config,
	)

	if err != nil {
		return err
	}

	if !allowed {
		return consts.OVER_SMS_SEND_RATE_LIMIT
	}

	return next()
}
