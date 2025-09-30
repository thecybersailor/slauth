package controller

import (
	"fmt"
	"log/slog"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/flow/password"
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

// extractUserIDFromToken Extract user ID from JWT
func (a *AuthController) extractUserIDFromToken(c *pin.Context) (string, error) {
	// Extract JWT
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", consts.NO_AUTHORIZATION
	}

	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if token == "" {
		return "", consts.BAD_JWT
	}

	// Validate JWT
	claims, err := a.authService.ValidateJWT(token)
	if err != nil {
		return "", consts.BAD_JWT
	}

	// Extract user ID
	userID, ok := claims["user_id"].(uint)
	if !ok {
		return "", consts.BAD_JWT
	}

	return fmt.Sprintf("%d", userID), nil
}
