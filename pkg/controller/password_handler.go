package controller

import (
	"log/slog"
	"time"

	"github.com/flaboy/pin"
	"github.com/flaboy/pin/usererrors"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/flow/password"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// ResetPasswordWithFlow Password reset handler using flow
// @Summary Reset Password
// @Description Reset user password using email/phone verification
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Password reset request"
// @Success 200 {object} map[string]interface{} "Password reset email sent"
// @Router /recover [post]
func (a *AuthController) ResetPasswordWithFlow(c *pin.Context) error {
	slog.Info("ResetPasswordWithFlow request received")

	req := &ResetPasswordRequest{}
	if err := c.BindJSON(req); err != nil {
		slog.Error("ResetPassword JSON binding failed", "error", err)
		return consts.BAD_JSON
	}

	// Check authService
	if a.authService == nil {
		slog.Error("AuthService is nil in ResetPassword")
		return consts.UNEXPECTED_FAILURE
	}

	// Create password reset context
	passwordCtx := password.NewPasswordContext(c.Request.Context(), a.authService, c.Request, req)

	ctx := &core.Context[core.PasswordResetData]{
		Data: core.PasswordResetData{
			Email:  req.Email,
			Phone:  req.Phone,
			Action: "password_reset",
		},
	}

	// Execute password reset flow
	requestFlow := password.RequestPasswordResetFlow(passwordCtx)
	err := requestFlow(ctx, func() error {
		// Send reset email
		if req.Email != "" {
			emailFlow := password.SendResetEmailFlow(passwordCtx)
			return emailFlow(ctx, func() error { return nil })
		}
		return nil
	})
	if err != nil {
		slog.Error("ResetPassword flow failed", "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	// Token generation and email sending are handled in flow, no additional check needed

	// Return response (always return success for security)
	return c.Render(map[string]string{"message": "Password reset email sent if account exists"})
}

// ResetPasswordWithToken handles reset password by recovery token without JWT.
// @Summary Reset Password With Token
// @Description Reset password by recovery token from email link
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordWithTokenRequest true "Reset password with token request"
// @Success 200 {object} map[string]string "Password updated"
// @Router /reset-password [put]
func (a *AuthController) ResetPasswordWithToken(c *pin.Context) error {
	req := &ResetPasswordWithTokenRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	if req.Token == "" || req.Password == "" {
		return consts.VALIDATION_FAILED
	}

	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("ResetPasswordWithToken failed to cast auth service")
		return consts.UNEXPECTED_FAILURE
	}

	instanceID := a.authService.GetInstanceId()
	tokenHash := services.HashToken(req.Token)
	otTokenService := authServiceImpl.GetOneTimeTokenService()

	isValid, err := otTokenService.IsValid(c.Request.Context(), tokenHash, instanceID, 24*time.Hour)
	if err != nil || !isValid {
		return usererrors.New("auth.invalid_recovery_token", "Invalid or expired reset token").SetHttpStatus(400)
	}

	otToken, err := otTokenService.GetByTokenHash(c.Request.Context(), tokenHash, instanceID)
	if err != nil || otToken == nil || otToken.UserID == nil || otToken.TokenType != types.OneTimeTokenTypeRecovery {
		return usererrors.New("auth.invalid_recovery_token", "Invalid or expired reset token").SetHttpStatus(400)
	}

	passwordService := a.authService.GetPasswordService()
	if !passwordService.ValidatePasswordStrength(req.Password) {
		return consts.WEAK_PASSWORD
	}

	hashedPassword, err := passwordService.HashPassword(req.Password)
	if err != nil {
		slog.Error("ResetPasswordWithToken hash password failed", "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	if err := a.authService.GetUserService().UpdatePassword(c.Request.Context(), *otToken.UserID, instanceID, hashedPassword); err != nil {
		slog.Error("ResetPasswordWithToken update password failed", "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	if err := otTokenService.Delete(c.Request.Context(), tokenHash, instanceID); err != nil {
		slog.Error("ResetPasswordWithToken delete token failed", "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	return c.Render(map[string]string{"message": "Password updated successfully"})
}
