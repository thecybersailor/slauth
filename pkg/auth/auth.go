package auth

import (
	"github.com/flaboy/aira-core/pkg/database"
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/controller"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/registry"
	"github.com/thecybersailor/slauth/pkg/services"
)

// ControllerRouteHandler implements RouteHandler interface
type ControllerRouteHandler struct {
	authService services.AuthService
}

func (h *ControllerRouteHandler) SetAuthService(authService services.AuthService) {
	h.authService = authService
}

func (h *ControllerRouteHandler) RegisterRoutes(router gin.IRouter) {
	controller.RegisterRoutes(router, h.authService)
}

// AdminRouteHandler implements admin route handler
type AdminRouteHandler struct {
	authService services.AuthService
}

func (h *AdminRouteHandler) SetAuthService(authService services.AuthService) {
	h.authService = authService
}

func (h *AdminRouteHandler) RegisterRoutes(router gin.IRouter) {
	// Register admin-related routes
	controller.RegisterAdminRoutes(router, h.authService)
}

// NewAuthServiceConfig creates a new AuthServiceConfig with default values
func NewAuthServiceConfig() *config.AuthServiceConfig {
	return config.NewAuthServiceConfig()
}

// NewService creates and registers a new auth service with global secrets
// The service will automatically load dynamic config from database
func NewService(domainCode, globalJWTSecret, globalAppSecret string) services.AuthService {
	authService := registry.RegisterAuthService(domainCode, globalJWTSecret, globalAppSecret, database.Database())

	// Set route handlers
	authService.SetRouteHandler(&ControllerRouteHandler{})
	authService.SetAdminRouteHandler(&AdminRouteHandler{})

	return authService
}

func Start() error {
	return models.Init()
}
