package main

import (
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/auth"
)

// @title slauth Platform API
// @version 1.0
// @description Complete authentication and administrative management API for Aira platform
// @termsOfService https://aira.com/terms

// @contact.name Aira API Support
// @contact.email support@aira.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @securityDefinitions.apikey AdminAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and admin JWT token.

func main() {
	// This is a documentation generation entry point
	// It only serves to register routes for swag to analyze

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	userAuth := auth.NewService("docs", "", "")

	// Register both auth and admin routes
	userAuth.HandleAuthRequest(r.Group("/auth"))
	userAuth.HandleAdminRequest(r.Group("/admin"))

	// This main function is never actually executed
	// It's only used by swag to analyze the route structure
}
