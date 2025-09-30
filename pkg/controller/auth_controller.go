package controller

import (
	"github.com/thecybersailor/slauth/pkg/services"
)

// AuthController handles authentication operations based on auth auth-js API
type AuthController struct {
	authService services.AuthService
}

// NewAuthController creates a new AuthController instance
func NewAuthController(authService services.AuthService) *AuthController {
	return &AuthController{
		authService: authService,
	}
}

// Note: All handler methods have been moved to separate files:
// - auth_handlers.go: Basic authentication methods (SignUp, SignInWithPassword, etc.)
// - oauth_handlers.go: OAuth and SSO related methods
// - token_handlers.go: Token management methods (RefreshToken, SignOut, etc.)
// - auth_types.go: All request/response type definitions
// - auth_helpers.go: Helper functions and utilities
