package controller

import (
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
