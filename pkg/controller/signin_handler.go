package controller

import (
	"log/slog"
	"time"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/flow/signin"
)

// SignInWithPasswordWithFlow Password login handler using flow
// @Summary Password Login
// @Description Authenticate user with email/phone and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SignInWithPasswordRequest true "Password login request"
// @Success 200 {object} AuthData "Login successful"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Invalid credentials"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /token [post]
func (a *AuthController) SignInWithPasswordWithFlow(c *pin.Context) error {
	slog.Info("SignInWithPasswordWithFlow request received")

	req := &SignInWithPasswordRequest{}
	if err := c.BindJSON(req); err != nil {
		slog.Error("SignIn JSON binding failed", "error", err)
		return consts.BAD_JSON
	}

	// Validate request parameters
	if err := validateSignInRequest(req); err != nil {
		slog.Error("SignIn validation failed", "error", err)
		return consts.VALIDATION_FAILED
	}

	// Check authService
	if a.authService == nil {
		slog.Error("AuthService is nil in SignIn")
		return consts.UNEXPECTED_FAILURE
	}

	// Create signin flow chain
	// Create signin context
	signinCtx := signin.NewSigninContext(c.Request.Context(), a.authService, c.Request, req)

	chain := signin.CreatePasswordSigninChain(c.Request, signinCtx)

	// Create flow context
	ctx := &core.Context[core.SigninData]{
		Data: core.SigninData{
			EmailOrPhone: req.Email,
			Password:     req.Password,
			Action:       "password_signin",
		},
	}

	// Execute flow chain
	err := chain.Execute(ctx)
	if err != nil {
		slog.Error("SignIn flow chain failed", "error", err)
		return err // Return original error instead of wrapping
	}

	// Authentication and session creation are handled in flow, no additional check needed

	// Get response data from SigninContext
	var userData *User
	var sessionData *Session

	if signinCtx.Response().User != nil {
		// Use convertUserToResponse to properly build response, including metadata
		userData = convertUserToResponse(signinCtx.Response().User.User)
	} else {
		// If no response data, use original logic
		userData = &User{
			ID:    ctx.Data.UserID,
			Email: req.Email,
		}
	}

	// Debug: Log session data before creating response
	slog.Info("SignInWithPassword: Creating session response",
		"ctxDataSessionID", ctx.Data.SessionID,
		"ctxDataSessionIDLength", len(ctx.Data.SessionID),
		"ctxDataAccessToken", ctx.Data.AccessToken,
		"ctxDataRefreshToken", ctx.Data.RefreshToken,
		"signinCtxResponseSession", signinCtx.Response().Session != nil)

	if signinCtx.Response().Session != nil {
		slog.Info("SignInWithPassword: Using session from SigninContext",
			"sessionHashID", signinCtx.Response().Session.HashID,
			"sessionID", signinCtx.Response().Session.ID)

		sessionData = &Session{
			ID:           ctx.Data.SessionID,
			AccessToken:  ctx.Data.AccessToken,
			RefreshToken: ctx.Data.RefreshToken,
			ExpiresIn:    int(ctx.Data.ExpiresIn - time.Now().Unix()),
			TokenType:    "Bearer",
			User:         userData, // Use the same user data
		}
	} else {
		slog.Info("SignInWithPassword: Using session from context data",
			"sessionID", ctx.Data.SessionID)

		sessionData = &Session{
			ID:           ctx.Data.SessionID,
			AccessToken:  ctx.Data.AccessToken,
			RefreshToken: ctx.Data.RefreshToken,
			ExpiresIn:    int(ctx.Data.ExpiresIn - time.Now().Unix()),
			TokenType:    "Bearer",
			User:         userData, // Use the same user data
		}
	}

	// Debug: Log final session data
	slog.Info("SignInWithPassword: Final session data",
		"sessionID", sessionData.ID,
		"accessToken", sessionData.AccessToken != "",
		"refreshToken", sessionData.RefreshToken != "")

	// Validate redirect URL
	redirectTo := ""
	if req.Options != nil && req.Options.RedirectTo != "" {
		redirectService := a.createRedirectService()
		redirectTo = redirectService.ValidateAndGetRedirectTo(req.Options.RedirectTo)
		slog.Info("SignInWithPassword: Redirect URL validated", "original", req.Options.RedirectTo, "validated", redirectTo)
	}

	// Return response
	resp := &AuthData{
		User:       userData,
		Session:    sessionData,
		RedirectTo: redirectTo,
	}

	return c.Render(resp)
}

// SignInWithOTPWithFlow OTP login handler using flow
// @Summary OTP Login
// @Description Authenticate user with OTP (One-Time Password)
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SignInWithOtpRequest true "OTP login request"
// @Success 200 {object} AuthData "OTP sent successfully"
// @Router /otp [post]
func (a *AuthController) SignInWithOTPWithFlow(c *pin.Context) error {
	slog.Info("SignInWithOTPWithFlow request received")

	req := &SignInWithOtpRequest{}
	if err := c.BindJSON(req); err != nil {
		slog.Error("SignInWithOTP JSON binding failed", "error", err)
		return consts.BAD_JSON
	}

	// Check authService
	if a.authService == nil {
		slog.Error("AuthService is nil in SignInWithOTP")
		return consts.UNEXPECTED_FAILURE
	}

	// TODO: OTP login needs separate OTPSigninContext, not implemented yet
	slog.Warn("SignInWithOTP flow not implemented yet - needs OTPSigninContext")
	return consts.UNEXPECTED_FAILURE
}

// SignInWithPassword Password login handler (for token endpoint)
func (a *AuthController) SignInWithPassword(c *pin.Context) error {
	// Directly call flow version
	return a.SignInWithPasswordWithFlow(c)
}
