package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

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
	domainCode      string

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
func NewAuthServiceImpl(db *gorm.DB, domainCode, globalJWTSecret, globalAppSecret string) *AuthServiceImpl {
	// Create config loader
	configLoader := NewConfigLoader(db, domainCode, globalJWTSecret, globalAppSecret)

	// Load config for the first time
	cfg := configLoader.GetConfig()

	jwtService := NewJWTService(
		cfg.JWTSecret,
		cfg.SessionConfig.AccessTokenTTL,
		cfg.SessionConfig.RefreshTokenTTL,
		cfg.AuthServiceBaseUrl,
	)

	// Initialize HashIDService and set as global instance
	hashIDService := NewHashIDService(cfg)
	SetGlobalHashIDService(hashIDService)

	userService := NewUserServiceWithDomain(db, domainCode)
	sessionService := NewSessionService(db)
	passwordService := NewPasswordService(nil, cfg.AppSecret, cfg.SecurityConfig.PasswordStrengthConfig.MinScore)

	return &AuthServiceImpl{
		db:              db,
		configLoader:    configLoader,
		jwtService:      jwtService,
		passwordService: passwordService,
		otpService:      NewOTPService(cfg.AuthServiceBaseUrl),
		validator:       NewValidatorService(),
		domainCode:      domainCode,

		// Initialize service layers
		userService:         userService,
		sessionService:      sessionService,
		refreshTokenService: NewRefreshTokenService(db),
		otTokenService:      NewOneTimeTokenService(db),

		// Initialize admin service layers
		adminSessionService:  NewAdminSessionService(db, sessionService),
		adminIdentityService: NewAdminIdentityService(db),
		adminSystemService:   NewAdminSystemService(db, userService, NewPasswordService(nil, cfg.AppSecret, cfg.SecurityConfig.PasswordStrengthConfig.MinScore), domainCode),

		// Initialize middleware slices
		signupMiddlewares:   make([]func(ctx SignupContext, next func() error) error, 0),
		signinMiddlewares:   make([]func(ctx SigninContext, next func() error) error, 0),
		passwordMiddlewares: make([]func(ctx PasswordContext, next func() error) error, 0),
		otpMiddlewares:      make([]func(ctx OTPContext, next func() error) error, 0),

		// Initialize builtin template resolver as fallback
		messageTemplateResolvers: []types.MessageTemplateResolver{
			NewBuiltinTemplateResolver(),
		},
	}
}

// AuthenticateUser authenticates user with email/phone and password
func (s *AuthServiceImpl) AuthenticateUser(ctx context.Context, emailOrPhone, password string) (*User, error) {
	slog.Info("AuthenticateUser called",
		"emailOrPhone", emailOrPhone,
		"hasPassword", password != "",
		"domainCode", s.domainCode,
	)

	if emailOrPhone == "" || password == "" {
		slog.Error("Missing email/phone or password")
		return nil, consts.VALIDATION_FAILED
	}

	// Find user
	var user models.User
	query := s.db.Where("domain_code = ?", s.domainCode)

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
	userObj, err := NewUserFromModel(&user, s.passwordService, s.sessionService, s.db, s.domainCode)
	if err != nil {
		slog.Error("Failed to create user object", "error", err, "userID", user.ID)
		return nil, consts.UNEXPECTED_FAILURE
	}

	return userObj, nil
}

// CreateSession creates a new session for user
func (s *AuthServiceImpl) CreateSession(ctx context.Context, user *User, aal types.AALLevel, amr []string, userAgent, ip string) (*Session, string, string, int64, error) {
	// Create session record
	now := time.Now()
	session := &models.Session{
		UserID:      user.ID,
		DomainCode:  s.domainCode,
		AAL:         &aal,
		CreatedAt:   now,
		UpdatedAt:   now,
		RefreshedAt: &now,
		UserAgent:   &userAgent,
		IP:          &ip,
	}

	if err := s.db.Create(session).Error; err != nil {
		return nil, "", "", 0, err
	}

	// SQLite auto increment fix: refresh the session to get the correct ID
	if session.ID == 0 {
		if err := s.db.First(session, "user_id = ? AND domain_code = ? AND created_at = ?",
			user.ID, s.domainCode, session.CreatedAt).Error; err != nil {
			return nil, "", "", 0, err
		}
	}

	// Debug: Check if session.ID was set correctly
	slog.Info("Session created", "sessionID", session.ID, "userID", user.ID, "domainCode", s.domainCode)

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
		user.HashID, s.domainCode, email, phone, "authenticated",
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
		DomainCode: s.domainCode,
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
		return nil, "", "", 0, err
	}

	// Update session refresh time and metadata
	now := time.Now()
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
		user.HashID, s.domainCode, email, phone, "authenticated",
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
		DomainCode: s.domainCode,
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
	err := s.db.WithContext(ctx).Preload("Session").Where("token = ? AND domain_code = ? AND (revoked IS NULL OR revoked = false)",
		tokenString, s.domainCode).First(&token).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, consts.REFRESH_TOKEN_NOT_FOUND
		}
		return nil, err
	}

	// Check if associated session is revoked
	if token.Session != nil && token.Session.NotAfter != nil {
		if token.Session.NotAfter.Before(time.Now()) {
			return nil, consts.SESSION_EXPIRED
		}
	}

	return &token, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *AuthServiceImpl) RevokeRefreshToken(ctx context.Context, tokenString string) error {
	result := s.db.Model(&models.RefreshToken{}).
		Where("token = ? AND domain_code = ?", tokenString, s.domainCode).
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
	err := s.db.WithContext(ctx).Where("id = ? AND domain_code = ?", id, s.domainCode).First(&flowState).Error
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
	err = s.db.Where("id = ? AND domain_code = ?", claims.SessionID, claims.DomainCode).First(&session).Error
	if err != nil {
		return nil, consts.SESSION_NOT_FOUND
	}

	// Check if session is revoked (not_after is set)
	if session.NotAfter != nil {
		return nil, consts.SESSION_EXPIRED
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
		"domain_code": claims.DomainCode,
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
func (s *AuthServiceImpl) GetMessageTemplate(domainCode, messageType, templateName string) (types.MessageTemplate, bool) {
	for _, resolver := range s.messageTemplateResolvers {
		if templateBytes, found := resolver.GetTemplate(domainCode, messageType, templateName); found {
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

func (s *AuthServiceImpl) GetDomainCode() string {
	return s.domainCode
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
	// Set domain middleware
	router.Use(s.domainMiddleware())

	// Call the configured route handler
	if s.authRouteHandler != nil {
		s.authRouteHandler.SetAuthService(s)
		s.authRouteHandler.RegisterRoutes(router)
	}
	return s
}

// HandleAdminRequest handles admin-related routes
func (s *AuthServiceImpl) HandleAdminRequest(router gin.IRouter) AuthService {
	// Set domain middleware
	router.Use(s.domainMiddleware())

	// Call the configured admin route handler
	if s.adminRouteHandler != nil {
		s.adminRouteHandler.SetAuthService(s)
		s.adminRouteHandler.RegisterRoutes(router)
	}
	return s
}

func (s *AuthServiceImpl) domainMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx := &AuthContext{
			DomainCode:  s.domainCode,
			AuthService: s,
		}
		SetAuthContext(c, authCtx)
		c.Next()
	}
}

// RequestValidator returns JWT validation middleware
func (s *AuthServiceImpl) RequestValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set domain context
		authCtx := &AuthContext{
			DomainCode:  s.domainCode,
			AuthService: s,
		}
		SetAuthContext(c, authCtx)

		// Extract JWT token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Missing authorization token"})
			c.Abort()
			return
		}

		var token string
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}

		if token == "" {
			c.JSON(401, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		// Validate JWT
		claims, err := s.ValidateJWT(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		authCtx.JWTToken = token
		authCtx.UserClaims = claims

		// Load user information
		userID, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid user ID in token"})
			c.Abort()
			return
		}

		user, err := s.GetUserService().GetByHashID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(401, gin.H{"error": "User not found"})
			c.Abort()
			return
		}
		authCtx.User = user.User

		c.Next()
	}
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
