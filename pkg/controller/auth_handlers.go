package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// VerifyOtp verifies OTP token for authentication
// @Summary Verify OTP
// @Description Verify OTP code for email/phone confirmation
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body VerifyOtpRequest true "OTP verification request"
// @Success 200 {object} AuthData "OTP verification successful"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 422 {object} map[string]interface{} "Invalid OTP code"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /verify [post]
func (a *AuthController) VerifyOtp(c *pin.Context) error {
	req := &VerifyOtpRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	slog.Info("VerifyEmailCode request received", "email", req.Email, "code", req.Token)

	// Validate required fields
	if req.Token == "" {
		slog.Warn("Invalid verification code length", "email", req.Email, "code_length", len(req.Token))
		return consts.VALIDATION_FAILED
	}

	if req.Email == "" && req.Phone == "" {
		return consts.VALIDATION_FAILED
	}

	// Get AuthServiceImpl instance
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("VerifyOtp: Invalid auth service type")
		return consts.UNEXPECTED_FAILURE
	}

	// Verify OTP
	otpService := authServiceImpl.GetOTPService()
	db := authServiceImpl.GetDB()
	instanceId := a.authService.GetInstanceId()

	valid, err := otpService.VerifyOTP(c.Request.Context(), req.Email, req.Phone, req.Token, types.OneTimeTokenTypeConfirmation, instanceId, db)
	if err != nil {
		slog.Warn("OTP verification failed", "error", err, "email", req.Email)
		return consts.VALIDATION_FAILED
	}

	if !valid {
		slog.Warn("Invalid OTP code", "email", req.Email)
		return consts.VALIDATION_FAILED
	}

	slog.Info("OTP verification successful", "email", req.Email)

	// Return success response
	resp := &SuccessResponse{
		Success: true,
	}

	return c.Render(resp)
}

// UpdateUser updates user profile information
// @Summary Update User Profile
// @Description Update user profile information
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateUserProfileRequest true "User profile update request"
// @Success 200 {object} UserResponse "Profile updated successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /user [put]
func (a *AuthController) UpdateUser(c *pin.Context) error {
	req := &UpdateUserProfileRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Extract JWT from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return consts.NO_AUTHORIZATION
	}

	// Extract token
	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if token == "" {
		return consts.BAD_JWT
	}

	// Validate JWT and extract user info
	claims, err := a.authService.ValidateJWT(token)
	if err != nil {
		return consts.BAD_JWT
	}

	// Extract user ID from claims
	userID, ok := claims["sub"].(string)
	if !ok {
		return consts.BAD_JWT
	}

	// Get user
	user, err := a.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// TODO: Update user profile in database
	// In a real implementation, this would:
	// 1. Validate new email/phone if provided
	// 2. Send confirmation emails/SMS if email/phone changed
	// 3. Update user metadata
	// 4. Hash new password if provided

	// Convert user to response format
	userResp := convertUserToResponse(user.GetModel())

	resp := &UserResponse{
		User: userResp,
	}

	return c.Render(resp)
}

// GetUser returns current user information
// @Summary Get Current User
// @Description Get current authenticated user information
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserResponse "User information retrieved successfully"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /user [get]
func (a *AuthController) GetUser(c *pin.Context) error {
	// Extract JWT from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return consts.NO_AUTHORIZATION
	}

	// Extract token
	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if token == "" {
		return consts.BAD_JWT
	}

	// Validate JWT and extract user info
	slog.Info("GetUser: Starting JWT validation", "tokenLength", len(token))
	claims, err := a.authService.ValidateJWT(token)
	if err != nil {
		slog.Warn("GetUser: JWT validation failed", "error", err.Error())
		return consts.BAD_JWT
	}
	slog.Info("GetUser: JWT validation successful", "claims", claims)

	// Extract user ID from claims
	userID, ok := claims["sub"].(string)
	if !ok {
		return consts.BAD_JWT
	}

	// Get user
	user, err := a.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Convert user to response format
	userResp := convertUserToResponse(user.GetModel())

	// Add AAL information from claims to the response
	if aal, exists := claims["aal"]; exists {
		userResp.AAL = aal
	}

	resp := &UserResponse{
		User: userResp,
	}

	return c.Render(resp)
}

// ConfirmEmail confirms user email using confirmation token
// @Summary Confirm Email
// @Description Confirm user email address using confirmation token
// @Tags Auth
// @Produce json
// @Param token query string true "Email confirmation token"
// @Success 200 {object} map[string]interface{} "Email confirmed successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 422 {object} map[string]interface{} "Invalid or expired token"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /confirm [get]
func (a *AuthController) ConfirmEmail(c *pin.Context) error {
	// Get token parameter
	token := c.Query("token")
	if token == "" {
		slog.Warn("ConfirmEmail: Missing token parameter")
		return consts.VALIDATION_FAILED
	}

	slog.Info("ConfirmEmail request received", "token", token[:8]+"...")

	// Get AuthServiceImpl instance
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("ConfirmEmail: Invalid auth service type")
		return consts.UNEXPECTED_FAILURE
	}

	// Get OneTimeTokenService
	otTokenService := authServiceImpl.GetOneTimeTokenService()

	// Calculate token hash
	tokenHash := services.HashToken(token)

	// Find token record
	otToken, err := otTokenService.GetWithUser(context.Background(), tokenHash, a.authService.GetInstanceId())
	if err != nil {
		slog.Warn("ConfirmEmail: Token not found", "error", err)
		return consts.VALIDATION_FAILED
	}

	// Check token type
	if otToken.TokenType != types.OneTimeTokenTypeConfirmation {
		slog.Warn("ConfirmEmail: Invalid token type", "type", otToken.TokenType)
		return consts.VALIDATION_FAILED
	}

	// Check if token is expired (24 hours)
	if time.Since(otToken.CreatedAt) > 24*time.Hour {
		slog.Warn("ConfirmEmail: Token expired", "created", otToken.CreatedAt)
		return consts.VALIDATION_FAILED
	}

	// Confirm user email
	userService := authServiceImpl.GetUserService()
	err = userService.ConfirmEmail(context.Background(), *otToken.UserID, a.authService.GetInstanceId())
	if err != nil {
		slog.Error("ConfirmEmail: Failed to confirm email", "error", err, "userID", otToken.UserID)
		return consts.UNEXPECTED_FAILURE
	}

	// Delete used token
	err = otTokenService.DeleteByID(context.Background(), otToken.ID, a.authService.GetInstanceId())
	if err != nil {
		slog.Warn("ConfirmEmail: Failed to delete token", "error", err, "tokenID", otToken.ID)
		// Don't return error because email has been confirmed successfully
	}

	slog.Info("ConfirmEmail: Email confirmed successfully", "userID", otToken.UserID)

	// Return success response
	resp := map[string]interface{}{
		"message": "Email confirmed successfully",
		"success": true,
	}

	return c.Render(resp)
}
