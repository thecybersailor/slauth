package controller

import (
	"log/slog"
	"strings"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	identitychange "github.com/thecybersailor/slauth/pkg/flow/identity_change"
	"github.com/thecybersailor/slauth/pkg/flow/otp"
	"github.com/thecybersailor/slauth/pkg/flow/password"
	"github.com/thecybersailor/slauth/pkg/flow/reauth"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// UserController handles user management operations
type UserController struct {
	authService services.AuthService
}

// ===== Request/Response Types =====

type UpdateUserRequest struct {
	Email        string             `json:"email,omitempty"`
	Phone        string             `json:"phone,omitempty"`
	Password     string             `json:"password,omitempty"`
	Nonce        string             `json:"nonce,omitempty"`
	UserMetadata map[string]any     `json:"user_metadata,omitempty"`
	Options      *UpdateUserOptions `json:"options,omitempty"`
}

type UpdateUserOptions struct {
	EmailRedirectTo string `json:"emailRedirectTo,omitempty"`
}

type UserData struct {
	User *User `json:"user,omitempty"`
}

type ResendRequest struct {
	Type    string         `json:"type"` // signup, email_change, sms, phone_change
	Email   string         `json:"email,omitempty"`
	Phone   string         `json:"phone,omitempty"`
	Options *ResendOptions `json:"options,omitempty"`
}

type ResendOptions struct {
	EmailRedirectTo string `json:"emailRedirectTo,omitempty"`
	CaptchaToken    string `json:"captchaToken,omitempty"`
}

// Session management types
type SessionData struct {
	Session *Session `json:"session,omitempty"`
}

// ===== Controller Methods =====

// GetUser retrieves current user information
// @Summary Get Current User
// @Description Get current authenticated user information
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserData "User information retrieved successfully"
// @Router /user [get]
func (u *UserController) GetUser(c *pin.Context) error {
	// Get current user from gin context
	user, err := u.authService.GetCurrentUser(c.Context)
	if err != nil {
		return err
	}

	// Convert to response format
	userResp := convertUserToResponse(u.authService, user.GetModel())

	resp := &UserData{
		User: userResp,
	}

	return c.Render(resp)
}

// UpdateUser updates user attributes
// @Summary Update User Profile
// @Description Update user profile attributes
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateUserRequest true "User update request"
// @Success 200 {object} UserData "User updated successfully"
// @Router /user [put]
func (u *UserController) UpdateUser(c *pin.Context) error {
	req := &UpdateUserRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	// Prepare updates
	updates := make(map[string]any)
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}
	if req.UserMetadata != nil {
		updates["user_data"] = req.UserMetadata
	}

	// Get user first
	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Update user metadata if provided
	if req.UserMetadata != nil {
		err = user.UpdateMetadata(c.Request.Context(), req.UserMetadata)
		if err != nil {
			return consts.UNEXPECTED_FAILURE
		}
	}

	// Convert to response format
	userResp := convertUserToResponse(u.authService, user.GetModel())

	resp := &UserData{
		User: userResp,
	}

	return c.Render(resp)
}

// Reauthenticate sends reauthentication OTP
// @Summary Start Reauthentication
// @Description Send a short-lived verification code to upgrade the current session assurance level.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ReauthenticateRequest false "Reauthentication request"
// @Success 200 {object} ReauthenticateData "Reauthentication challenge sent successfully"
// @Router /reauthenticate [post]
func (u *UserController) Reauthenticate(c *pin.Context) error {
	req := &ReauthenticateRequest{}
	if c.Request.ContentLength > 0 {
		if err := c.BindJSON(req); err != nil {
			return consts.BAD_JSON
		}
	}

	authHeader := c.GetHeader("Authorization")
	token := extractBearerToken(authHeader)
	if token == "" {
		if authHeader == "" {
			return consts.NO_AUTHORIZATION
		}
		return consts.BAD_JWT
	}

	claims, err := u.authService.ValidateJWT(token)
	if err != nil {
		return consts.BAD_JWT
	}

	userID, err := extractUserIDFromToken(claims)
	if err != nil {
		return err
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	result, err := reauth.SendChallenge(c.Request.Context(), u.authService, user, req.Channel)
	if err != nil {
		return err
	}

	currentLevel := types.AALLevel1
	if currentAAL, ok := claims["aal"].(types.AALLevel); ok && currentAAL != "" {
		currentLevel = currentAAL
	}

	resp := &ReauthenticateData{
		MessageID:    result.MessageID,
		SessionCode:  result.SessionCode,
		Channel:      result.Channel,
		CurrentLevel: string(currentLevel),
		NextLevel:    string(types.AALLevel2),
		ExpiresAt:    &result.ExpiresAt,
	}

	return c.Render(resp)
}

// VerifyReauthentication verifies the challenge and upgrades the current session AAL.
// @Summary Verify Reauthentication
// @Description Verify the reauthentication challenge and upgrade the current session assurance level.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyReauthenticateRequest true "Reauthentication verification request"
// @Success 200 {object} ReauthenticateVerifyData "Session assurance upgraded successfully"
// @Router /reauthenticate/verify [post]
func (u *UserController) VerifyReauthentication(c *pin.Context) error {
	req := &VerifyReauthenticateRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	sessionID, err := u.extractSessionIDFromToken(c)
	if err != nil {
		return err
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	result, err := reauth.VerifyChallenge(
		c.Request.Context(),
		u.authService,
		user,
		sessionID,
		req.Channel,
		req.Token,
		req.SessionCode,
	)
	if err != nil {
		return err
	}

	resp := &ReauthenticateVerifyData{
		Success:      true,
		Channel:      result.Channel,
		CurrentLevel: string(types.AALLevel2),
		ExpiresAt:    result.ExpiresAt.Unix(),
	}

	return c.Render(resp)
}

// StartSecureEmailChange starts the secure email change flow.
// @Summary Start Secure Email Change
// @Description Start a secure multi-step email change flow.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body StartEmailChangeRequest true "Secure email change request"
// @Success 200 {object} IdentityChangeData "Secure email change flow started"
// @Router /email/change [post]
func (u *UserController) StartSecureEmailChange(c *pin.Context) error {
	req := &StartEmailChangeRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	user, currentAAL, err := u.getCurrentUserAndAAL(c)
	if err != nil {
		return err
	}

	result, err := identitychange.Start(c.Request.Context(), u.authService, user, identitychange.KindEmail, req.Email, currentAAL)
	if err != nil {
		return err
	}

	flowID, err := encodeFlowID(result.FlowStateID)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	return c.Render(&IdentityChangeData{
		FlowID:      flowID,
		SessionCode: result.SessionCode,
		Stage:       string(result.Stage),
		Channel:     result.Channel,
		Completed:   false,
	})
}

// VerifySecureEmailChange verifies a secure email change flow step.
// @Summary Verify Secure Email Change
// @Description Verify the current step in a secure email change flow.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyIdentityChangeRequest true "Secure email change verification request"
// @Success 200 {object} IdentityChangeData "Secure email change flow advanced"
// @Router /email/change/verify [post]
func (u *UserController) VerifySecureEmailChange(c *pin.Context) error {
	return u.verifySecureIdentityChange(c, identitychange.KindEmail)
}

// StartSecurePhoneChange starts the secure phone change flow.
// @Summary Start Secure Phone Change
// @Description Start a secure multi-step phone change flow.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body StartPhoneChangeRequest true "Secure phone change request"
// @Success 200 {object} IdentityChangeData "Secure phone change flow started"
// @Router /phone/change [post]
func (u *UserController) StartSecurePhoneChange(c *pin.Context) error {
	req := &StartPhoneChangeRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	user, currentAAL, err := u.getCurrentUserAndAAL(c)
	if err != nil {
		return err
	}

	result, err := identitychange.Start(c.Request.Context(), u.authService, user, identitychange.KindPhone, req.Phone, currentAAL)
	if err != nil {
		return err
	}

	flowID, err := encodeFlowID(result.FlowStateID)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	return c.Render(&IdentityChangeData{
		FlowID:      flowID,
		SessionCode: result.SessionCode,
		Stage:       string(result.Stage),
		Channel:     result.Channel,
		Completed:   false,
	})
}

// VerifySecurePhoneChange verifies a secure phone change flow step.
// @Summary Verify Secure Phone Change
// @Description Verify the current step in a secure phone change flow.
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyIdentityChangeRequest true "Secure phone change verification request"
// @Success 200 {object} IdentityChangeData "Secure phone change flow advanced"
// @Router /phone/change/verify [post]
func (u *UserController) VerifySecurePhoneChange(c *pin.Context) error {
	return u.verifySecureIdentityChange(c, identitychange.KindPhone)
}

// Resend resends confirmation email/SMS
// @Summary Resend Verification Code
// @Description Resend verification code for signup, email change, or phone change
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResendRequest true "Resend verification request"
// @Success 200 {object} map[string]interface{} "Verification code resent successfully"
// @Router /resend [post]
func (u *UserController) Resend(c *pin.Context) error {
	req := &ResendRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate request type
	validTypes := []string{"signup", "email_change", "sms", "phone_change"}
	isValidType := false
	for _, validType := range validTypes {
		if req.Type == validType {
			isValidType = true
			break
		}
	}

	if !isValidType {
		return consts.VALIDATION_FAILED
	}

	// Implement resend logic using flow chains
	var messageID string
	var sessionCode string

	switch req.Type {
	case "signup", "email_change":
		// Resend email verification using OTP flow
		if req.Email == "" {
			return consts.VALIDATION_FAILED
		}

		otpRequest := &types.SendOTPRequest{
			Email: req.Email,
		}

		otpCtx := otp.NewOTPContext(c.Request.Context(), u.authService, c.Request, otpRequest)

		chain := otp.CreateOTPChain(otpCtx)
		err := chain.Execute(otpCtx)
		if err != nil {
			slog.Error("Failed to resend email verification", "email", req.Email, "error", err)
			return err
		}

		messageID = otpCtx.Response().MessageID
		sessionCode = otpCtx.Response().SessionCode

	case "sms", "phone_change":
		// Resend SMS verification using OTP flow
		if req.Phone == "" {
			return consts.VALIDATION_FAILED
		}

		otpRequest := &types.SendOTPRequest{
			Phone: req.Phone,
		}

		otpCtx := otp.NewOTPContext(c.Request.Context(), u.authService, c.Request, otpRequest)

		chain := otp.CreateOTPChain(otpCtx)
		err := chain.Execute(otpCtx)
		if err != nil {
			slog.Error("Failed to resend SMS verification", "phone", req.Phone, "error", err)
			return err
		}

		messageID = otpCtx.Response().MessageID
		sessionCode = otpCtx.Response().SessionCode

	default:
		return consts.VALIDATION_FAILED
	}

	slog.Info("Resend request processed successfully", "type", req.Type, "email", req.Email, "phone", req.Phone, "messageID", messageID)

	type ResendData struct {
		User        *User  `json:"user"`
		Session     *User  `json:"session"`
		MessageID   string `json:"messageId,omitempty"`
		SessionCode string `json:"session_code,omitempty"`
	}

	resp := &ResendData{
		User:        nil,
		Session:     nil,
		MessageID:   messageID,
		SessionCode: sessionCode,
	}

	return c.Render(resp)
}

// GetSession retrieves current session
// GET /session (internal method, usually handled by middleware)
func (u *UserController) GetSession(c *pin.Context) error {

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

	// TODO: Validate JWT and get session data
	// For now, return placeholder session

	resp := &SessionData{
		Session: &Session{
			AccessToken:  token,
			RefreshToken: "placeholder-refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			User:         nil, // TODO: populate user data
		},
	}

	return c.Render(resp)
}

// SetSession sets session data (for server-side usage)
// POST /session (internal method)
func (u *UserController) SetSession(c *pin.Context) error {
	type SetSessionRequest struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	req := &SetSessionRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate required fields
	if req.AccessToken == "" {
		return consts.VALIDATION_FAILED
	}

	// TODO: Validate tokens and store session data
	// For now, return the provided session data

	resp := &SessionData{
		Session: &Session{
			AccessToken:  req.AccessToken,
			RefreshToken: req.RefreshToken,
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			User:         nil, // TODO: populate user data from token
		},
	}

	return c.Render(resp)
}

// ===== Helper Methods =====

func (u *UserController) extractUserIDFromToken(c *pin.Context) (string, error) {
	// Extract JWT from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", consts.NO_AUTHORIZATION
	}

	// Extract token
	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if token == "" {
		return "", consts.BAD_JWT
	}

	// Validate JWT and extract user claims
	claims, err := u.authService.ValidateJWT(token)
	if err != nil {
		return "", consts.BAD_JWT
	}

	// Extract user ID from claims
	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", consts.BAD_JWT
	}

	return userID, nil
}

func (u *UserController) extractSessionIDFromToken(c *pin.Context) (uint, error) {
	// Extract JWT from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return 0, consts.NO_AUTHORIZATION
	}

	// Extract token
	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if token == "" {
		return 0, consts.BAD_JWT
	}

	// Validate JWT and extract session ID
	claims, err := u.authService.ValidateJWT(token)
	if err != nil {
		return 0, consts.BAD_JWT
	}

	// Extract session ID from claims
	sessionIDRaw := claims["session_id"]
	var sessionID uint
	switch v := sessionIDRaw.(type) {
	case float64:
		sessionID = uint(v)
	case int:
		sessionID = uint(v)
	case uint:
		sessionID = v
	default:
		return 0, consts.BAD_JWT
	}

	return sessionID, nil
}

func (u *UserController) getCurrentUserAndAAL(c *pin.Context) (*services.User, types.AALLevel, error) {
	authHeader := c.GetHeader("Authorization")
	token := extractBearerToken(authHeader)
	if token == "" {
		if authHeader == "" {
			return nil, "", consts.NO_AUTHORIZATION
		}
		return nil, "", consts.BAD_JWT
	}

	claims, err := u.authService.ValidateJWT(token)
	if err != nil {
		return nil, "", consts.BAD_JWT
	}

	userID, err := extractUserIDFromToken(claims)
	if err != nil {
		return nil, "", err
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return nil, "", consts.USER_NOT_FOUND
	}

	currentAAL := types.AALLevel1
	if claimAAL, ok := claims["aal"].(types.AALLevel); ok && claimAAL != "" {
		currentAAL = claimAAL
	}

	return user, currentAAL, nil
}

func (u *UserController) verifySecureIdentityChange(c *pin.Context, kind identitychange.Kind) error {
	req := &VerifyIdentityChangeRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	flowStateID, err := decodeFlowID(req.FlowID)
	if err != nil {
		return consts.VALIDATION_FAILED
	}

	result, err := identitychange.Verify(c.Request.Context(), u.authService, user, flowStateID, kind, req.Token, req.SessionCode)
	if err != nil {
		return err
	}

	return c.Render(&IdentityChangeData{
		FlowID:      req.FlowID,
		SessionCode: result.SessionCode,
		Stage:       string(result.Stage),
		Channel:     result.Channel,
		Completed:   result.Completed,
	})
}

// ===== New User Management Methods =====

// @Summary Update User Password
// @Description Update user password with verification
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdatePasswordRequest true "Password update request"
// @Success 200 {object} UserResponse "Password update initiated successfully"
// @Router /password [put]
func (u *UserController) UpdatePasswordWithFlow(c *pin.Context) error {
	slog.Info("UpdatePasswordWithFlow request received")

	req := &UpdatePasswordRequest{}
	if err := c.BindJSON(req); err != nil {
		slog.Error("UpdatePassword JSON binding failed", "error", err)
		return consts.BAD_JSON
	}

	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	if u.authService == nil {
		slog.Error("AuthService is nil in UpdatePassword")
		return consts.UNEXPECTED_FAILURE
	}

	updatePasswordReq := &types.UpdatePasswordRequest{
		Password: req.Password,
		Nonce:    req.Nonce,
	}

	passwordUpdateCtx := password.NewPasswordUpdateContext(c.Request.Context(), u.authService, c.Request, updatePasswordReq, userID)

	ctx := &core.Context[core.PasswordChangeData]{
		Context: c.Request.Context(),
		Data: core.PasswordChangeData{
			UserID:      userID,
			NewPassword: req.Password,
			Action:      "password_update",
		},
	}

	chain := password.CreatePasswordUpdateChain(passwordUpdateCtx)
	err = chain.Execute(ctx)
	if err != nil {
		slog.Error("UpdatePassword flow failed", "error", err)

		if err == consts.INSUFFICIENT_AAL {
			return consts.INSUFFICIENT_AAL
		}
		if err == consts.OVER_REQUEST_RATE_LIMIT {
			return consts.OVER_REQUEST_RATE_LIMIT
		}

		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "insufficient_aal") || strings.Contains(errMsg, "insufficient aal") {
			return consts.INSUFFICIENT_AAL
		}
		if strings.Contains(errMsg, "rate limit") {
			return consts.OVER_REQUEST_RATE_LIMIT
		}
		return consts.UNEXPECTED_FAILURE
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		slog.Error("Failed to get user after password update", "error", err)

		resp := &UserResponse{
			User: &User{
				ID: userID,
			},
		}
		return c.Render(resp)
	}

	userResp := convertUserToResponse(u.authService, user.GetModel())

	resp := &UserResponse{
		User: userResp,
	}

	return c.Render(resp)
}

// UpdateEmail updates user email
// @Summary Update User Email
// @Description Update user email address
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object{email=string} true "Email update request"
// @Success 200 {object} SuccessResponse "Email update initiated successfully"
// @Router /email [put]
func (u *UserController) UpdateEmail(c *pin.Context) error {
	req := &struct {
		Email string `json:"email" binding:"required,email"`
	}{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Extract user ID from JWT
	_, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	otpRequest := &types.SendOTPRequest{
		Email: req.Email,
	}

	otpCtx := otp.NewOTPContext(c.Request.Context(), u.authService, c.Request, otpRequest)

	chain := otp.CreateOTPChain(otpCtx)
	err = chain.Execute(otpCtx)
	if err != nil {
		slog.Error("Failed to send email change verification code", "email", req.Email, "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	slog.Info("Email change verification code sent successfully", "email", req.Email)

	resp := map[string]any{
		"user":         nil,
		"session_code": otpCtx.Response().SessionCode,
	}

	return c.Render(resp)
}

// VerifyEmailChange verifies email change with OTP
// @Summary Verify Email Change
// @Description Verify email change with OTP token
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object{email=string,token=string} true "Email verification request"
// @Success 200 {object} map[string]interface{} "Email change verified successfully"
// @Router /email/verify [post]
func (u *UserController) VerifyEmailChange(c *pin.Context) error {
	req := &struct {
		Email       string `json:"email" binding:"required,email"`
		Token       string `json:"token" binding:"required"`
		SessionCode string `json:"session_code" binding:"required"`
	}{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	authServiceImpl, ok := u.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("VerifyEmailChange: Invalid auth service type")
		return consts.UNEXPECTED_FAILURE
	}

	otpService := authServiceImpl.GetOTPService()
	db := authServiceImpl.GetDB()
	instanceId := u.authService.GetInstanceId()

	valid, err := otpService.VerifyOTP(c.Request.Context(), req.Email, "", req.Token, req.SessionCode, types.OneTimeTokenTypeConfirmation, instanceId, db)
	if err != nil {
		slog.Warn("Email change OTP verification failed", "error", err, "email", req.Email)
		return consts.VALIDATION_FAILED
	}

	if !valid {
		slog.Warn("Invalid email change OTP code", "email", req.Email)
		return consts.VALIDATION_FAILED
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	err = user.UpdateEmail(c.Request.Context(), req.Email)
	if err != nil {
		slog.Error("Failed to update user email", "error", err, "userID", userID, "newEmail", req.Email)
		return consts.UNEXPECTED_FAILURE
	}

	slog.Info("Email change verified and updated successfully", "userID", userID, "newEmail", req.Email)

	resp := &SuccessResponse{
		Success: true,
	}

	return c.Render(resp)
}

// UpdatePhone updates user phone
// @Summary Update User Phone
// @Description Update user phone number
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object{phone=string} true "Phone update request"
// @Success 200 {object} SuccessResponse "Phone update initiated successfully"
// @Router /phone [put]
func (u *UserController) UpdatePhone(c *pin.Context) error {
	req := &struct {
		Phone string `json:"phone" binding:"required"`
	}{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Extract user ID from JWT
	_, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	otpRequest := &types.SendOTPRequest{
		Phone: req.Phone,
	}

	otpCtx := otp.NewOTPContext(c.Request.Context(), u.authService, c.Request, otpRequest)

	chain := otp.CreateOTPChain(otpCtx)
	err = chain.Execute(otpCtx)
	if err != nil {
		slog.Error("Failed to send phone change verification code", "phone", req.Phone, "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	slog.Info("Phone change verification code sent successfully", "phone", req.Phone)

	resp := map[string]any{
		"user":         nil,
		"session_code": otpCtx.Response().SessionCode,
	}

	return c.Render(resp)
}

// VerifyPhoneChange verifies phone change with OTP
// @Summary Verify Phone Change
// @Description Verify phone change with OTP token
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object{phone=string,token=string} true "Phone verification request"
// @Success 200 {object} map[string]interface{} "Phone change verified successfully"
// @Router /phone/verify [post]
func (u *UserController) VerifyPhoneChange(c *pin.Context) error {
	req := &struct {
		Phone       string `json:"phone" binding:"required"`
		Token       string `json:"token" binding:"required"`
		SessionCode string `json:"session_code" binding:"required"`
	}{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	authServiceImpl, ok := u.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("VerifyPhoneChange: Invalid auth service type")
		return consts.UNEXPECTED_FAILURE
	}

	otpService := authServiceImpl.GetOTPService()
	db := authServiceImpl.GetDB()
	instanceId := u.authService.GetInstanceId()

	valid, err := otpService.VerifyOTP(c.Request.Context(), "", req.Phone, req.Token, req.SessionCode, types.OneTimeTokenTypeConfirmation, instanceId, db)
	if err != nil {
		slog.Warn("Phone change OTP verification failed", "error", err, "phone", req.Phone)
		return consts.VALIDATION_FAILED
	}

	if !valid {
		slog.Warn("Invalid phone change OTP code", "phone", req.Phone)
		return consts.VALIDATION_FAILED
	}

	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	err = user.UpdatePhone(c.Request.Context(), req.Phone)
	if err != nil {
		slog.Error("Failed to update user phone", "error", err, "userID", userID, "newPhone", req.Phone)
		return consts.UNEXPECTED_FAILURE
	}

	slog.Info("Phone change verified and updated successfully", "userID", userID, "newPhone", req.Phone)

	resp := &SuccessResponse{
		Success: true,
	}

	return c.Render(resp)
}

// GetUserSessions gets user's active sessions
// @Summary Get User Sessions
// @Description Get user's active sessions
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} ListSessionsResponse "Sessions retrieved successfully"
// @Router /sessions [get]
func (u *UserController) GetUserSessions(c *pin.Context) error {
	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	// Parse query parameters
	var req ListSessionsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set defaults and validate
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}

	// Get user first
	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Get user sessions
	sessions, err := user.GetActiveSessions(c.Request.Context())
	if err != nil {
		return err
	}

	// Simple pagination (since GetActiveSessions doesn't support pagination yet)
	total := int64(len(sessions))
	start := (req.Page - 1) * req.PageSize
	end := start + req.PageSize
	if start >= len(sessions) {
		sessions = []*services.Session{}
	} else {
		if end > len(sessions) {
			end = len(sessions)
		}
		sessions = sessions[start:end]
	}

	// Convert to response format
	response := ListSessionsResponse{
		Sessions: convertSessionsToResponse(u.authService, sessions),
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}

	return c.Render(response)
}

// RevokeSession revokes a specific session
// @Summary Revoke Session
// @Description Revoke a specific user session
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Param id path string true "Session ID"
// @Success 200 {object} map[string]interface{} "Session revoked successfully"
// @Router /sessions/{id} [delete]
func (u *UserController) RevokeSession(c *pin.Context) error {
	sessionID := c.Param("id")
	if sessionID == "" {
		return consts.VALIDATION_FAILED
	}

	// Extract user ID from JWT to verify session ownership
	_, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	// Use admin service to revoke session (since we need to verify ownership)
	err = u.authService.GetAdminSessionService().RevokeUserSession(c.Request.Context(), u.authService.GetInstanceId(), sessionID)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	resp := map[string]string{
		"message": "Session revoked successfully",
	}

	return c.Render(resp)
}

// RevokeAllSessions revokes all user sessions
// @Summary Revoke All Sessions
// @Description Revoke all user sessions with option to exclude current session
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Param exclude_current query bool false "Exclude current session from revocation" default(false)
// @Success 200 {object} map[string]interface{} "All sessions revoked successfully"
// @Router /sessions [delete]
func (u *UserController) RevokeAllSessions(c *pin.Context) error {
	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	// Get current session ID from JWT
	sessionID, err := u.extractSessionIDFromToken(c)
	if err != nil {
		return err
	}

	// Get user
	user, err := u.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Check if we should exclude current session
	excludeCurrent := c.Query("exclude_current") == "true"

	if excludeCurrent {
		// Revoke all sessions except current
		err = user.RevokeAllSessionsExcept(c.Request.Context(), sessionID)
	} else {
		// Revoke all sessions including current
		err = user.RevokeAllSessions(c.Request.Context())
	}

	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	var message string
	if excludeCurrent {
		message = "All other sessions revoked successfully"
	} else {
		message = "All sessions revoked successfully"
	}

	resp := map[string]string{
		"message": message,
	}

	return c.Render(resp)
}

// GetAuditLog gets user's audit log
// @Summary Get Audit Log
// @Description Get user's security audit log
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} GetAuditLogResponse "Audit log retrieved successfully"
// @Router /security/audit-log [get]
func (u *UserController) GetAuditLog(c *pin.Context) error {
	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	// TODO: Implement audit log retrieval
	// userID will be used to get audit log for the specific user
	_ = userID // Suppress unused variable warning
	resp := &types.GetAuditLogResponse{
		Events: []map[string]interface{}{},
	}

	return c.Render(resp)
}

// GetDevices gets user's registered devices
// @Summary Get Devices
// @Description Get user's registered devices
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} GetDevicesResponse "Devices retrieved successfully"
// @Router /security/devices [get]
func (u *UserController) GetDevices(c *pin.Context) error {
	// Extract user ID from JWT
	userID, err := u.extractUserIDFromToken(c)
	if err != nil {
		return err
	}

	// TODO: Implement device listing
	// userID will be used to get devices for the specific user
	_ = userID // Suppress unused variable warning
	resp := &types.GetDevicesResponse{
		Devices: []map[string]interface{}{},
	}

	return c.Render(resp)
}
