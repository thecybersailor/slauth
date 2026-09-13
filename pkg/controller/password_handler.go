package controller

import (
	"log/slog"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
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

	if req.Email != "" {
		if err := services.NewPasswordRecoveryService(a.authService).Request(c.Request.Context(), req.Email); err != nil {
			slog.Error("ResetPassword request failed", "error", err)
			return err
		}
	}

	// Return response (always return success for security)
	return c.Render(map[string]string{"message": "Password reset email sent if account exists"})
}
