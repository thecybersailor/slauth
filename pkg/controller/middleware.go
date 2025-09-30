package controller

import (
	"net/http"
	"strings"

	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/services"
)

// JWTAuthMiddleware validates JWT tokens and sets user context
func JWTAuthMiddleware(authService *services.AuthServiceImpl) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": map[string]any{
					"message": "Authorization header required",
					"status":  401,
					"code":    "missing_authorization",
				},
			})
			c.Abort()
			return
		}

		// Check Bearer format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": map[string]any{
					"message": "Invalid authorization header format",
					"status":  401,
					"code":    "invalid_authorization_format",
				},
			})
			c.Abort()
			return
		}

		// Extract token
		token := authHeader[7:] // Remove "Bearer " prefix

		// TODO: Validate JWT token using authService
		// For now, just set the auth service in context
		c.Set("auth_service", authService)
		c.Set("jwt_token", token)

		c.Next()
	}
}

// OptionalJWTAuthMiddleware validates JWT tokens if present but doesn't require them
func OptionalJWTAuthMiddleware(authService *services.AuthServiceImpl) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")

		// Set auth service in context regardless
		c.Set("auth_service", authService)

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token := authHeader[7:] // Remove "Bearer " prefix
			c.Set("jwt_token", token)

			// TODO: Validate JWT token and set user context if valid
		}

		c.Next()
	}
}

// RateLimitMiddleware implements basic rate limiting
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement rate limiting logic
		// For now, just pass through
		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Requested-With, X-Client-Info, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// ErrorHandlerMiddleware handles errors and formats responses
func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			err := c.Errors.Last()

			// Format error response
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": map[string]any{
					"message": err.Error(),
					"status":  500,
					"code":    "internal_server_error",
				},
			})
		}
	}
}

// LoggingMiddleware logs requests
func LoggingMiddleware() gin.HandlerFunc {
	return gin.Logger()
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.Recovery()
}

// PinContextAdapter adapts gin.Context to pin.Context for middleware compatibility
func PinContextAdapter(handler func(*pin.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create pin context from gin context
		pinCtx := &pin.Context{
			Context: c,
		}

		// Call the handler
		if err := handler(pinCtx); err != nil {
			if errResult := c.Error(err); errResult != nil {
				return
			}
		}
	}
}
