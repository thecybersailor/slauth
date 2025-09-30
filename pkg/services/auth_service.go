package services

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type RouteHandler interface {
	SetAuthService(authService AuthService)
	RegisterRoutes(router gin.IRouter)
}

type AuthService interface {
	AuthenticateUser(ctx context.Context, emailOrPhone, password string) (*User, error)

	CreateSession(ctx context.Context, user *User, aal types.AALLevel, amr []string, userAgent, ip string) (*Session, string, string, int64, error)
	ValidateJWT(token string) (map[string]any, error)

	ValidateRefreshToken(ctx context.Context, tokenString string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenString string) error

	CreateFlowState(ctx context.Context, flowState *models.FlowState) error
	GetFlowStateByID(ctx context.Context, id uint) (*models.FlowState, error)
	UpdateFlowState(ctx context.Context, flowState *models.FlowState) error
	DeleteFlowState(ctx context.Context, id uint) error

	SetCaptchaProvider(provider types.CaptchaProvider) AuthService
	AddIdentityProvider(provider types.IdentityProvider) AuthService
	GetIdentityProvider(name string) (types.IdentityProvider, bool)
	AddMFAProvider(provider types.MFAProvider) AuthService
	GetMFAProvider(name string) (types.MFAProvider, bool)
	SetSMSProvider(provider types.SMSProvider) AuthService
	SetEmailProvider(provider types.EmailProvider) AuthService
	GetEmailProvider() types.EmailProvider
	GetSMSProvider() types.SMSProvider
	RegisterMessageTemplateResolver(resolver types.MessageTemplateResolver) AuthService

	SetRouteHandler(handler RouteHandler) AuthService
	SetAdminRouteHandler(handler RouteHandler) AuthService

	HandleAuthRequest(router gin.IRouter) AuthService
	HandleAdminRequest(router gin.IRouter) AuthService
	RequestValidator() gin.HandlerFunc

	GenerateOTPCode(ctx OTPContext) (string, error)
	GetOTPService() *OTPService
	GetDB() *gorm.DB

	GetDomainCode() string
	GetConfig() *config.AuthServiceConfig
	GetUserService() *UserService
	SaveConfig(cfg *config.AuthServiceConfig) error

	GetAdminSessionService() *AdminSessionService
	GetAdminIdentityService() *AdminIdentityService
	GetAdminSystemService() *AdminSystemService

	GetMessageTemplate(domainCode, messageType, templateName string) (types.MessageTemplate, bool)

	SignupUse(middleware func(ctx SignupContext, next func() error) error) AuthService
	SigninUse(middleware func(ctx SigninContext, next func() error) error) AuthService
	PasswordUse(middleware func(ctx PasswordContext, next func() error) error) AuthService
	OTPUse(middleware func(ctx OTPContext, next func() error) error) AuthService
}
