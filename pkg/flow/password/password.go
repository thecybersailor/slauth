package password

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// passwordContextImpl Implements services.PasswordContext interface
type passwordContextImpl struct {
	context.Context
	service     services.AuthService
	httpRequest *http.Request
	request     *types.ResetPasswordRequest
	response    *services.PasswordResponse
	trigger     services.FlowTrigger
}

func (p *passwordContextImpl) Service() services.AuthService {
	return p.service
}

func (p *passwordContextImpl) HttpRequest() *http.Request {
	return p.httpRequest
}

func (p *passwordContextImpl) Request() *types.ResetPasswordRequest {
	return p.request
}

func (p *passwordContextImpl) Response() *services.PasswordResponse {
	if p.response == nil {
		p.response = &services.PasswordResponse{}
	}
	return p.response
}

func (p *passwordContextImpl) GetTrigger() services.FlowTrigger {
	return p.trigger
}

// NewPasswordContext Create new PasswordContext
func NewPasswordContext(ctx context.Context, service services.AuthService, httpRequest *http.Request, request *types.ResetPasswordRequest) services.PasswordContext {
	return &passwordContextImpl{
		Context:     ctx,
		service:     service,
		httpRequest: httpRequest,
		request:     request,
		trigger:     services.TriggerHttpRequest, // Default to HTTP request trigger
	}
}

func RequestPasswordResetFlow(passwordCtx services.PasswordContext) core.Flow[core.PasswordResetData] {
	return func(ctx *core.Context[core.PasswordResetData], next func() error) error {
		slog.Info("Flow: RequestPasswordReset - Before")

		// Find user first
		var user interface{}
		var err error
		if ctx.Data.Email != "" {
			user, err = passwordCtx.Service().GetUserService().GetByEmail(passwordCtx, ctx.Data.Email)
		} else if ctx.Data.Phone != "" {
			// TODO: Add GetUserByPhone to UserService
			slog.Warn("Flow: RequestPasswordReset - GetUserByPhone not implemented")
		}

		if err != nil {
			slog.Warn("Flow: RequestPasswordReset - User not found", "error", err)
			// Return success without sending email to prevent user enumeration
			passwordCtx.Response().Success = true
			return nil
		}

		ctx.User = user

		resetToken := "dummy_reset_token"
		resetURL := fmt.Sprintf("%s/auth/reset-password?token=%s", passwordCtx.Service().GetConfig().AuthServiceBaseUrl, resetToken)

		ctx.Data.ResetURL = resetURL
		ctx.Data.Token = resetToken

		passwordCtx.Response().ResetURL = resetURL
		passwordCtx.Response().Token = resetToken
		passwordCtx.Response().Success = true

		slog.Info("Flow: RequestPasswordReset - Reset token generated", "email", ctx.Data.Email, "phone", ctx.Data.Phone)
		return next()
	}
}

// SendResetEmailFlow Send password reset email flow
func SendResetEmailFlow(passwordCtx services.PasswordContext) core.Flow[core.PasswordResetData] {
	return core.EmailFlow[core.PasswordResetData](
		core.EmailFlowConfig{
			AuthService:   passwordCtx.Service(),
			EmailProvider: passwordCtx.Service().GetEmailProvider(),
			TemplateName:  "reset-password",
			MessageType:   "email",
			InstanceId:    passwordCtx.Service().GetInstanceId(),
		},
		func(data core.PasswordResetData) string {
			return data.Email
		},
		func(data core.PasswordResetData) map[string]interface{} {
			return map[string]interface{}{
				"ResetURL": data.ResetURL,
			}
		},
	)
}

// TODO: SendResetSMSFlow Temporarily commented, needs further improvement

// ===== Password update related flows =====

// passwordUpdateContextImpl Implements services.PasswordUpdateContext interface
type passwordUpdateContextImpl struct {
	context.Context
	service     services.AuthService
	httpRequest *http.Request
	request     *types.UpdatePasswordRequest
	response    *services.PasswordUpdateResponse
	trigger     services.FlowTrigger
	userID      string
}

func (p *passwordUpdateContextImpl) Service() services.AuthService {
	return p.service
}

func (p *passwordUpdateContextImpl) HttpRequest() *http.Request {
	return p.httpRequest
}

func (p *passwordUpdateContextImpl) Request() *types.UpdatePasswordRequest {
	return p.request
}

func (p *passwordUpdateContextImpl) Response() *services.PasswordUpdateResponse {
	if p.response == nil {
		p.response = &services.PasswordUpdateResponse{}
	}
	return p.response
}

func (p *passwordUpdateContextImpl) GetTrigger() services.FlowTrigger {
	return p.trigger
}

func (p *passwordUpdateContextImpl) UserID() string {
	return p.userID
}

// NewPasswordUpdateContext Create new PasswordUpdateContext
func NewPasswordUpdateContext(ctx context.Context, service services.AuthService, httpRequest *http.Request, request *types.UpdatePasswordRequest, userID string) services.PasswordUpdateContext {
	return &passwordUpdateContextImpl{
		Context:     ctx,
		service:     service,
		httpRequest: httpRequest,
		request:     request,
		trigger:     services.TriggerHttpRequest,
		userID:      userID,
	}
}

// UpdatePasswordFlow Password update flow
func UpdatePasswordFlow(passwordCtx services.PasswordUpdateContext) core.Flow[core.PasswordChangeData] {
	return func(ctx *core.Context[core.PasswordChangeData], next func() error) error {
		slog.Info("Flow: UpdatePassword - Start", "userID", ctx.Data.UserID)

		config := passwordCtx.Service().GetConfig()
		rateLimit := config.SecurityConfig.PasswordUpdateConfig.RateLimit

		authServiceImpl, ok := passwordCtx.Service().(*services.AuthServiceImpl)
		if !ok {
			slog.Error("Flow: UpdatePassword - Failed to cast AuthService")
			return consts.UNEXPECTED_FAILURE
		}

		// Get numeric ID from userID string
		user, err := authServiceImpl.GetUserService().GetByHashID(ctx.Context, ctx.Data.UserID)
		if err != nil {
			slog.Error("Flow: UpdatePassword - Failed to get user", "error", err)
			return consts.USER_NOT_FOUND
		}

		userModel := user.GetModel()
		// Get AppSecret for RateLimit isolation
		appSecret := ""
		if authServiceImpl, ok := passwordCtx.Service().(*services.AuthServiceImpl); ok {
			appSecret = authServiceImpl.GetConfig().AppSecret
		}
		rateLimitService := services.NewRateLimitService(appSecret)

		// Ensure rate limit table exists (Redis doesn't need it, but keep for compatibility)
		err = rateLimitService.EnsureTableExists(ctx.Context)
		if err != nil {
			slog.Warn("Flow: UpdatePassword - Failed to ensure rate limit table exists", "error", err)
			// Don't return error, continue execution
		}

		allowed, err := rateLimitService.CheckAndRecordRequest(
			ctx.Context,
			userModel.ID,
			"password_update",
			passwordCtx.Service().GetInstanceId(),
			rateLimit,
			config,
		)
		if err != nil {
			slog.Error("Flow: UpdatePassword - Rate limit check failed", "error", err)
			return consts.UNEXPECTED_FAILURE
		}

		if !allowed {
			slog.Warn("Flow: UpdatePassword - Rate limit exceeded", "userID", ctx.Data.UserID)
			return consts.OVER_REQUEST_RATE_LIMIT
		}

		slog.Info("Flow: UpdatePassword - Rate limit check passed", "userID", ctx.Data.UserID)

		// 2. Check AAL level
		requiredAAL := config.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL

		authHeader := passwordCtx.HttpRequest().Header.Get("Authorization")
		if authHeader == "" {
			slog.Error("Flow: UpdatePassword - No authorization header")
			return consts.NO_AUTHORIZATION
		}

		token := ""
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}

		if token == "" {
			slog.Error("Flow: UpdatePassword - Invalid token format")
			return consts.BAD_JWT
		}

		claims, err := passwordCtx.Service().ValidateJWT(token)
		if err != nil {
			slog.Error("Flow: UpdatePassword - JWT validation failed", "error", err)
			return consts.BAD_JWT
		}

		aalValue := claims["aal"]

		var currentAAL string
		switch v := aalValue.(type) {
		case string:
			currentAAL = v
		case types.AALLevel:
			currentAAL = string(v)
		default:
			slog.Error("Flow: UpdatePassword - AAL has unexpected type", "type", fmt.Sprintf("%T", aalValue), "value", aalValue)
			return consts.BAD_JWT
		}

		slog.Info("Flow: UpdatePassword - AAL check", "currentAAL", currentAAL, "requiredAAL", requiredAAL)

		if types.AALLevel(currentAAL) != requiredAAL {
			slog.Error("Flow: UpdatePassword - Insufficient AAL level", "current", currentAAL, "required", requiredAAL)
			return consts.INSUFFICIENT_AAL
		}

		// If AAL level meets requirement, reset password update rate limit
		// This allows users to update password immediately after AAL upgrade
		if types.AALLevel(currentAAL) == types.AALLevel2 {
			slog.Info("Flow: UpdatePassword - AAL2 detected, resetting rate limit", "userID", ctx.Data.UserID)
			// Clear password update rate limit record for this user using RateLimitService
			rateLimitService := passwordCtx.Service().(*services.AuthServiceImpl).GetRateLimitService()
			if rateLimitService != nil {
				rateLimitService.ClearUserActionRateLimit(ctx.Context, userModel.ID, "password_update", passwordCtx.Service().GetInstanceId(), config)
			}
		}

		// 3. Update password (using previously fetched user object)
		err = user.UpdatePassword(passwordCtx, ctx.Data.NewPassword)
		if err != nil {
			slog.Error("Flow: UpdatePassword - Password update failed", "error", err)
			return consts.UNEXPECTED_FAILURE
		}

		// 4. Revoke other sessions (if configured)
		if config.SecurityConfig.PasswordUpdateConfig.RevokeOtherSessions {

			authHeader := passwordCtx.HttpRequest().Header.Get("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token := authHeader[7:]
				claims, err := passwordCtx.Service().ValidateJWT(token)
				if err == nil {
					// Extract session ID
					if sessionIDRaw, ok := claims["session_id"]; ok {
						var sessionID uint
						switch v := sessionIDRaw.(type) {
						case float64:
							sessionID = uint(v)
						case int:
							sessionID = uint(v)
						case uint:
							sessionID = v
						default:
							slog.Warn("Flow: UpdatePassword - Invalid session ID type in JWT", "sessionID", sessionIDRaw)
							sessionID = 0
						}

						if sessionID > 0 {
							// Generate session HashID
							sessionHashID, err := services.GenerateSessionHashID(sessionID)
							if err != nil {
								slog.Warn("Flow: UpdatePassword - Failed to generate session hash ID", "error", err)
								// Fallback to revoking all sessions
								err = user.RevokeAllSessions(passwordCtx)
								if err != nil {
									slog.Warn("Flow: UpdatePassword - Failed to revoke all sessions", "error", err)
								}
							} else {
								// Revoke all sessions except current one
								err = user.RevokeAllSessionsExcept(passwordCtx, sessionID)
								if err != nil {
									slog.Warn("Flow: UpdatePassword - Failed to revoke other sessions", "error", err)
									// Don't return error because password has been updated successfully
								} else {
									slog.Info("Flow: UpdatePassword - Successfully revoked other sessions", "userID", ctx.Data.UserID, "currentSessionID", sessionHashID)
								}
							}
						} else {
							slog.Warn("Flow: UpdatePassword - Invalid session ID, revoking all sessions")
							err = user.RevokeAllSessions(passwordCtx)
							if err != nil {
								slog.Warn("Flow: UpdatePassword - Failed to revoke all sessions", "error", err)
							}
						}
					} else {
						slog.Warn("Flow: UpdatePassword - No session ID in JWT claims")
						err = user.RevokeAllSessions(passwordCtx)
						if err != nil {
							slog.Warn("Flow: UpdatePassword - Failed to revoke all sessions", "error", err)
						}
					}
				} else {
					slog.Warn("Flow: UpdatePassword - Failed to validate JWT for session extraction", "error", err)
					err = user.RevokeAllSessions(passwordCtx)
					if err != nil {
						slog.Warn("Flow: UpdatePassword - Failed to revoke all sessions", "error", err)
					}
				}
			} else {
				slog.Warn("Flow: UpdatePassword - No Authorization header found")
				err = user.RevokeAllSessions(passwordCtx)
				if err != nil {
					slog.Warn("Flow: UpdatePassword - Failed to revoke all sessions", "error", err)
				}
			}
		}

		// 5. Set response
		passwordCtx.Response().Success = true
		passwordCtx.Response().Message = "Password updated successfully"

		slog.Info("Flow: UpdatePassword - Success", "userID", ctx.Data.UserID)
		return next()
	}
}

// CreatePasswordUpdateChain Create password update flow chain
func CreatePasswordUpdateChain(passwordCtx services.PasswordUpdateContext) *core.Chain[core.PasswordChangeData] {
	return core.NewChain[core.PasswordChangeData](
		UpdatePasswordFlow(passwordCtx),
	)
}
