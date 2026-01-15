package controller

import (
	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/services"
)

func RegisterRoutes(parent gin.IRouter, authService services.AuthService) {
	// Initialize controllers with AuthService
	authController := &AuthController{authService: authService}
	userController := &UserController{authService: authService}

	// Apply CORS middleware to all routes
	parent.Use(CORSMiddleware())

	// Handle all OPTIONS requests for CORS preflight
	parent.OPTIONS("/*path", func(c *gin.Context) { c.Status(204) })

	// ===== Public JWKS Endpoint =====
	// JWKS endpoint for JWT verification (no authentication required)
	parent.GET("/.well-known/jwks.json", HandleJWKS(authService.GetSecretsProvider(), authService.GetInstanceId()))

	// ===== Public Authentication Routes =====
	// These routes don't require authentication

	// User Registration & Authentication
	parent.POST("/signup", pin.HandleFunc(authController.SignUpWithFlow)) // FLOW: User registration - requires user creation, email confirmation, middleware support
	parent.POST("/token", pin.HandleFunc(func(c *pin.Context) error {     // FLOW: Login process - requires authentication, session creation, MFA check
		return handleTokenEndpoint(c, authService)
	}))
	parent.POST("/otp", pin.HandleFunc(authController.SendVerificationCode))        // FLOW: OTP sending - requires code generation, email sending, rate limiting
	parent.POST("/sms-otp", pin.HandleFunc(authController.SendSMSVerificationCode)) // FLOW: SMS OTP - requires code generation, SMS sending, rate limiting
	parent.POST("/verify", pin.HandleFunc(authController.VerifyEmailCode))          // SIMPLE: OTP verification - simple code validation logic
	parent.POST("/resend", pin.HandleFunc(userController.Resend))                   // FLOW: Resend verification - requires rate limiting, multi-channel sending

	// Email Confirmation
	parent.GET("/confirm", pin.HandleFunc(authController.ConfirmEmail)) // SIMPLE: Email confirmation - simple token validation and status update

	// Password Management
	parent.POST("/recover", pin.HandleFunc(authController.ResetPasswordWithFlow)) // FLOW: Password reset - requires email sending, token generation, security checks

	// OAuth & SSO
	parent.POST("/authorize", pin.HandleFunc(authController.SignInWithOAuth))      // FLOW: OAuth login - requires third-party verification, user creation/association, session management
	parent.POST("/sso", pin.HandleFunc(authController.SignInWithSSO))              // FLOW: SSO login - requires SAML processing, user mapping, session management
	parent.POST("/sso/callback", pin.HandleFunc(authController.HandleSSOCallback)) // FLOW: SSO callback - processes SAML response, creates session

	userGroup := parent.Group("")
	userGroup.Use(authService.RequestValidator())
	registerUserRoutes(userGroup, authService)
}

// RegisterUserRoutes registers user management routes
func registerUserRoutes(parent gin.IRouter, authService services.AuthService) {
	// Initialize user controller with AuthService
	authController := &AuthController{authService: authService}
	mfaController := &MFAController{authService: authService}
	userController := &UserController{authService: authService}

	// User Management
	parent.GET("/user", pin.HandleFunc(userController.GetUser))    // SIMPLE: Get user info - direct database query
	parent.PUT("/user", pin.HandleFunc(userController.UpdateUser)) // FLOW: User info update - requires validation, audit log, email/phone change confirmation

	// Session Management
	parent.POST("/logout", pin.HandleFunc(authController.SignOut))       // SIMPLE: Logout - simple session revocation
	parent.POST("/refresh", pin.HandleFunc(authController.RefreshToken)) // SIMPLE: Refresh token - simple token validation and generation

	// Multi-Factor Authentication
	parent.POST("/factors/enroll", pin.HandleFunc(mfaController.Enroll))         // FLOW: MFA enrollment - requires code sending, device binding, backup code generation
	parent.POST("/factors/challenge", pin.HandleFunc(mfaController.Challenge))   // SIMPLE: MFA challenge - simple challenge generation
	parent.POST("/factors/verify", pin.HandleFunc(mfaController.Verify))         // SIMPLE: MFA verification - simple code validation
	parent.DELETE("/factors/:factor_id", pin.HandleFunc(mfaController.Unenroll)) // FLOW: MFA unenrollment - requires identity confirmation, backup code handling, security notification
	parent.GET("/factors", pin.HandleFunc(mfaController.ListFactors))            // SIMPLE: MFA list - direct database query

	// Password Management
	parent.PUT("/password", pin.HandleFunc(userController.UpdatePasswordWithFlow))

	// Email Management
	parent.PUT("/email", pin.HandleFunc(userController.UpdateEmail))               // FLOW: Email change - requires code sending, old email confirmation, new email verification
	parent.POST("/email/verify", pin.HandleFunc(userController.VerifyEmailChange)) // SIMPLE: Email change verification - simple code validation

	// Phone Management
	parent.PUT("/phone", pin.HandleFunc(userController.UpdatePhone))               // FLOW: Phone change - requires code sending, old phone confirmation, new phone verification
	parent.POST("/phone/verify", pin.HandleFunc(userController.VerifyPhoneChange)) // SIMPLE: Phone change verification - simple code validation

	// Session Management
	parent.GET("/sessions", pin.HandleFunc(userController.GetUserSessions))      // SIMPLE: Session list - direct database query
	parent.DELETE("/sessions/:id", pin.HandleFunc(userController.RevokeSession)) // SIMPLE: Revoke session - simple session deletion
	parent.DELETE("/sessions", pin.HandleFunc(userController.RevokeAllSessions)) // SIMPLE: Revoke all sessions - batch session deletion

	// Account Security
	parent.GET("/security/audit-log", pin.HandleFunc(userController.GetAuditLog)) // SIMPLE: Audit log - direct database query
	parent.GET("/security/devices", pin.HandleFunc(userController.GetDevices))    // SIMPLE: Device list - direct database query
}

// handleTokenEndpoint routes different grant types to appropriate handlers
func handleTokenEndpoint(c *pin.Context, authService services.AuthService) error {
	grantType := c.Query("grant_type")

	authController := &AuthController{authService: authService}

	switch grantType {
	case "password":
		return authController.SignInWithPassword(c)
	case "refresh_token":
		return authController.RefreshToken(c)
	case "pkce":
		return authController.ExchangeCodeForSession(c)
	case "id_token":
		return authController.SignInWithIdToken(c)
	default:
		return authController.SignInWithPassword(c)
	}
}

/*
Flow vs Simple Route Classification:

FLOW routes require complex business logic with multiple steps, middleware support, and state management:
- User registration, login, password reset
- OTP sending, MFA enrollment/unenrollment
- Email/phone change with verification
- OAuth/SSO authentication
- Admin operations with audit logging

SIMPLE routes are straightforward operations that can be handled directly:
- Data retrieval (GET requests)
- Simple status updates
- Token validation and generation
- Session revocation
- Statistics and reporting

This classification helps determine which routes need the full Flow architecture
and which can use simpler controller methods.
*/

// RegisterAdminRoutes registers admin-related routes
func RegisterAdminRoutes(parent gin.IRouter, authService services.AuthService) {
	// Initialize admin controller with AuthService
	adminController := &AdminController{authService: authService}

	// Apply CORS middleware to all routes
	parent.Use(CORSMiddleware())

	// Handle all OPTIONS requests for CORS preflight
	parent.OPTIONS("/*path", func(c *gin.Context) { c.Status(204) })

	// ===== Admin Routes =====
	// These routes require admin authentication

	// User Management
	parent.POST("/users/query", pin.HandleFunc(adminController.QueryUsers))                         // Query users with complex filters (Strapi-style)
	parent.GET("/users/:id", pin.HandleFunc(adminController.GetUser))                               // SIMPLE: Get user - direct database query
	parent.PUT("/users/:id", pin.HandleFunc(adminController.UpdateUser))                            // FLOW: Admin update user - requires audit log, user notification, data validation
	parent.DELETE("/users/:id", pin.HandleFunc(adminController.DeleteUser))                         // FLOW: Delete user - requires data cleanup, audit log, related data processing
	parent.POST("/users", pin.HandleFunc(adminController.CreateUser))                               // FLOW: Admin create user - requires email sending, password generation, audit log
	parent.POST("/users/:id/reset-password", pin.HandleFunc(adminController.ResetUserPassword))     // FLOW: Admin reset password - requires email notification, temporary password, audit log
	parent.PUT("/users/:id/email-confirmed", pin.HandleFunc(adminController.SetUserEmailConfirmed)) // SIMPLE: Set email confirmed status - simple status update
	parent.PUT("/users/:id/phone-confirmed", pin.HandleFunc(adminController.SetUserPhoneConfirmed)) // SIMPLE: Set phone confirmed status - simple status update

	// Session Management
	parent.GET("/users/:id/sessions", pin.HandleFunc(adminController.ListUserSessions))         // SIMPLE: User session list - direct database query
	parent.DELETE("/sessions/:id", pin.HandleFunc(adminController.RevokeUserSession))           // SIMPLE: Revoke session - simple session deletion
	parent.DELETE("/users/:id/sessions", pin.HandleFunc(adminController.RevokeAllUserSessions)) // SIMPLE: Revoke all sessions - batch session deletion
	parent.GET("/sessions", pin.HandleFunc(adminController.ListAllSessions))                    // SIMPLE: All sessions list - direct database query

	// Identity Management
	parent.GET("/users/:id/identities", pin.HandleFunc(adminController.ListUserIdentities))                 // SIMPLE: User identity list - direct database query
	parent.DELETE("/users/:id/identities/:identity_id", pin.HandleFunc(adminController.DeleteUserIdentity)) // FLOW: Delete identity - requires validation, audit log, related cleanup

	// System Management
	parent.GET("/stats/users", pin.HandleFunc(adminController.GetUserCount))              // SIMPLE: User statistics - simple statistics query
	parent.GET("/stats/sessions", pin.HandleFunc(adminController.GetActiveSessionCount))  // SIMPLE: Session statistics - simple statistics query
	parent.GET("/stats/recent-signups", pin.HandleFunc(adminController.GetRecentSignups)) // SIMPLE: Recent signups - simple query
	parent.GET("/stats/recent-signins", pin.HandleFunc(adminController.GetRecentSignins)) // SIMPLE: Recent signins - simple query

	// SAML SSO Management
	parent.POST("/saml/providers", pin.HandleFunc(adminController.CreateSAMLProvider))        // FLOW: Create SAML provider - requires validation, audit log
	parent.GET("/saml/providers", pin.HandleFunc(adminController.ListSAMLProviders))          // SIMPLE: List SAML providers - direct database query
	parent.GET("/saml/providers/:id", pin.HandleFunc(adminController.GetSAMLProvider))        // SIMPLE: Get SAML provider - direct database query
	parent.PUT("/saml/providers/:id", pin.HandleFunc(adminController.UpdateSAMLProvider))     // FLOW: Update SAML provider - requires validation, audit log
	parent.DELETE("/saml/providers/:id", pin.HandleFunc(adminController.DeleteSAMLProvider))  // FLOW: Delete SAML provider - requires cleanup, audit log
	parent.POST("/saml/providers/:id/test", pin.HandleFunc(adminController.TestSAMLProvider)) // SIMPLE: Test SAML provider - validation check

	// Config Management
	parent.GET("/config", pin.HandleFunc(adminController.GetInstanceConfig))    // SIMPLE: Get instance config
	parent.PUT("/config", pin.HandleFunc(adminController.UpdateInstanceConfig)) // SIMPLE: Update instance config
}
