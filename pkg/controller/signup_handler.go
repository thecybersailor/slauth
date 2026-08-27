package controller

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/flow/otp"
	"github.com/thecybersailor/slauth/pkg/flow/signup"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// @Summary User Registration
// @Description Register a new user with email/phone and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SignUpRequest true "User registration request"
// @Success 200 {object} AuthData "Registration successful"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 422 {object} map[string]interface{} "User already exists"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /signup [post]
func (a *AuthController) SignUpWithFlow(c *pin.Context) error {
	slog.Info("SignUpWithFlow request received")

	req := &SignUpRequest{}
	if err := c.BindJSON(req); err != nil {
		slog.Error("SignUp JSON binding failed", "error", err)
		return consts.BAD_JSON
	}

	slog.Info("SignUp request parsed",
		"email", req.Email,
		"phone", req.Phone,
		"hasPassword", req.Password != "",
	)

	if a.authService == nil {
		slog.Error("AuthService is nil in SignUp")
		return consts.UNEXPECTED_FAILURE
	}

	// Check if this is an anonymous sign-up
	isAnonymous := false
	if req.Options != nil && req.Options.Data != nil {
		if val, ok := req.Options.Data["is_anonymous"].(bool); ok && val {
			isAnonymous = true
		}
	}

	// Check sign-up/sign-in rate limit first
	config := a.authService.GetConfig()
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if ok {
		rateLimitService := authServiceImpl.GetRateLimitService()
		// Use email or phone as userKey for signup
		var userKey any = req.Email
		if req.Email == "" {
			userKey = req.Phone
		}
		allowed, err := rateLimitService.CheckAndRecordRequest(
			c.Request.Context(),
			userKey,
			"signup_signin",
			a.authService.GetInstanceId(),
			config.RatelimitConfig.SignUpSignInRateLimit,
			config,
		)
		if err != nil {
			slog.Error("SignUp: Rate limit check failed", "error", err)
			return err
		}
		if !allowed {
			slog.Warn("SignUp: Rate limit exceeded")
			return consts.OVER_REQUEST_RATE_LIMIT
		}
	}

	// Check configuration based on signup type
	if isAnonymous {
		// Check if anonymous sign-ins are allowed
		if config.AnonymousSignIns == nil || !*config.AnonymousSignIns {
			slog.Warn("SignUp: Anonymous sign-ins are disabled")
			return consts.ANONYMOUS_PROVIDER_DISABLED
		}
	} else {
		// Check if new user registration is allowed
		if config.AllowNewUsers == nil || !*config.AllowNewUsers {
			slog.Warn("SignUp: New user registration is disabled")
			return consts.SIGNUPS_DISABLED
		}
	}

	signupCtx := signup.NewSignupContext(c.Request.Context(), a.authService, c.Request, req)

	chain := signup.CreateSignupChain(c.Request, signupCtx)

	userMetaData := make(map[string]interface{})
	if req.UserMetadata != nil {
		for k, v := range req.UserMetadata {
			userMetaData[k] = v
		}
	}

	ctx := &core.Context[core.SignupData]{
		Data: core.SignupData{
			Email:    req.Email,
			Phone:    req.Phone,
			Password: req.Password,
			UserData: userMetaData,
			Action:   "user_signup",
		},
	}

	err := chain.Execute(ctx)
	if err != nil {
		slog.Error("SignUp flow chain failed", "error", err)

		if errors.Is(err, consts.USER_ALREADY_EXISTS) || strings.Contains(err.Error(), "user_already_exists") {
			return consts.USER_ALREADY_EXISTS
		}
		if errors.Is(err, consts.WEAK_PASSWORD) || strings.Contains(err.Error(), "weak_password") {
			return consts.WEAK_PASSWORD
		}
		if errors.Is(err, consts.VALIDATION_FAILED) || strings.Contains(err.Error(), "validation_failed") {
			return consts.VALIDATION_FAILED
		}
		if errors.Is(err, consts.EMAIL_ADDRESS_INVALID) || strings.Contains(err.Error(), "email_address_invalid") {
			return consts.EMAIL_ADDRESS_INVALID
		}
		return consts.UNEXPECTED_FAILURE
	}

	var userData *User
	if signupCtx.Response().User != nil {
		userData = convertUserToResponse(signupCtx.Service(), signupCtx.Response().User.User)
	} else {
		userData = &User{
			ID:    ctx.Data.UserID,
			Email: req.Email,
			Phone: req.Phone,
		}
	}

	// Validate redirect URL
	redirectTo := ""
	if req.Options != nil && req.Options.RedirectTo != "" {
		redirectService := a.createRedirectService()
		redirectTo = redirectService.ValidateAndGetRedirectTo(req.Options.RedirectTo)
		slog.Info("SignUp: Redirect URL validated", "original", req.Options.RedirectTo, "validated", redirectTo)
	}

	// If email confirmation is disabled, create session automatically
	var sessionData *Session

	slog.Info("SignUp: Checking email confirmation config",
		"confirm_email_ptr", config.ConfirmEmail,
		"confirm_email_val", config.ConfirmEmail != nil && *config.ConfirmEmail)

	if (config.ConfirmEmail == nil || !*config.ConfirmEmail) && signupCtx.Response().User != nil {
		user := signupCtx.Response().User
		slog.Info("SignUp: Email confirmation disabled, creating session", "userID", user.ID)

		// Create session using authService (same as OAuth/SignIn)
		session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
			c.Request.Context(), user, "aal1", []string{"email"},
			c.GetHeader("User-Agent"), c.ClientIP(),
		)
		if err != nil {
			slog.Error("SignUp: Failed to create session", "error", err)
			return consts.UNEXPECTED_FAILURE
		}

		slog.Info("SignUp: Session created", "sessionID", session.HashID)

		// Calculate expires_in from expires_at
		expiresIn := int(expiresAt - time.Now().Unix())
		if expiresIn < 0 {
			expiresIn = 0
		}

		sessionData = &Session{
			ID:           session.HashID,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    expiresIn,
			ExpiresAt:    expiresAt,
			User:         userData,
		}
	}

	resp := &AuthData{
		User:       userData,
		Session:    sessionData,
		RedirectTo: redirectTo,
	}

	return c.Render(resp)
}

// @Summary Send Email Verification Code
// @Description Send verification code to user's email address
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SendOTPRequest true "Email verification request"
// @Success 200 {object} SendOTPResponse "Verification code sent successfully"
// @Router /otp [post]
func (a *AuthController) SendVerificationCode(c *pin.Context) error {
	req := &SignInWithOtpRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	slog.Info("SendVerificationCode request received", "email", req.Email)

	if req.Email == "" && req.Phone == "" {
		return consts.VALIDATION_FAILED
	}

	if req.Email != "" && !isValidEmail(req.Email) {
		return consts.VALIDATION_FAILED
	}

	if shouldSendMagicLink(req) {
		return a.sendMagicLink(c, req)
	}

	if req.Phone != "" {
		normalizedPhone, ok := normalizePhone(req.Phone)
		if !ok {
			return consts.VALIDATION_FAILED
		}
		req.Phone = normalizedPhone
	}

	otpReq := &types.SendOTPRequest{
		Email: req.Email,
		Phone: req.Phone,
	}

	otpCtx := otp.NewOTPContext(c.Request.Context(), a.authService, c.Request, otpReq)

	chain := otp.CreateOTPChain(otpCtx)
	err := chain.Execute(otpCtx)
	if err != nil {
		slog.Error("Failed to send verification code", "error", err, "email", req.Email, "phone", req.Phone)
		return err
	}

	slog.Info("Verification code sent successfully", "email", req.Email, "phone", req.Phone)

	resp := &SendOTPResponse{
		MessageID:   otpCtx.Response().MessageID,
		SessionCode: otpCtx.Response().SessionCode,
	}

	return c.Render(resp)
}

func shouldSendMagicLink(req *SignInWithOtpRequest) bool {
	if req == nil || strings.TrimSpace(req.Email) == "" || req.Options == nil {
		return false
	}
	return strings.TrimSpace(req.Options.EmailRedirectTo) != "" || strings.TrimSpace(req.Options.RedirectTo) != ""
}

func (a *AuthController) sendMagicLink(c *pin.Context, req *SignInWithOtpRequest) error {
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("sendMagicLink: invalid auth service type")
		return consts.UNEXPECTED_FAILURE
	}
	email := strings.TrimSpace(req.Email)
	redirectTo := strings.TrimSpace(req.Options.EmailRedirectTo)
	if redirectTo == "" {
		redirectTo = strings.TrimSpace(req.Options.RedirectTo)
	}
	if redirectTo == "" {
		return consts.VALIDATION_FAILED
	}
	validator := services.NewValidatorService()
	if err := validator.ValidateEmail(email); err != nil {
		return consts.VALIDATION_FAILED
	}
	email = validator.SanitizeEmail(email)
	redirectTo, err := a.createRedirectService().ValidateAndGetRedirectToOrError(redirectTo)
	if err != nil {
		slog.Warn("sendMagicLink: redirect URL is not allowed", "redirect_to", redirectTo, "error", err)
		return consts.VALIDATION_FAILED
	}
	allowed, err := authServiceImpl.GetRateLimitService().CheckAndRecordRequest(
		c.Request.Context(),
		email,
		"email_send",
		a.authService.GetInstanceId(),
		a.authService.GetConfig().RatelimitConfig.EmailRateLimit,
		a.authService.GetConfig(),
	)
	if err != nil {
		return err
	}
	if !allowed {
		return consts.OVER_EMAIL_SEND_RATE_LIMIT
	}
	emailProvider := a.authService.GetEmailProvider()
	if emailProvider == nil {
		slog.Error("sendMagicLink: email provider not configured")
		return consts.UNEXPECTED_FAILURE
	}

	user, err := authServiceImpl.GetUserService().GetByEmail(c.Request.Context(), email)
	if err != nil {
		if !req.Options.ShouldCreateUser {
			slog.Warn("sendMagicLink: user not found and shouldCreateUser is false", "email", email, "error", err)
			return consts.INVALID_CREDENTIALS
		}
		user, err = authServiceImpl.GetUserService().CreateUserWithSource(
			c.Request.Context(),
			&services.UserCreateOptions{
				Email:        &email,
				UserMetadata: req.Options.Data,
			},
			services.UserCreatedSourceMagicLink,
			nil,
			c.Request,
		)
		if err != nil {
			slog.Error("sendMagicLink: failed to create user", "email", email, "error", err)
			return err
		}
	}

	plainToken, tokenHash, err := services.GenerateConfirmationToken()
	if err != nil {
		slog.Error("sendMagicLink: failed to generate token", "error", err)
		return consts.UNEXPECTED_FAILURE
	}
	if err := authServiceImpl.GetOneTimeTokenService().DeleteByUserIDAndType(
		c.Request.Context(),
		user.User.ID,
		types.OneTimeTokenTypeMagicLink,
		a.authService.GetInstanceId(),
	); err != nil {
		slog.Error("sendMagicLink: failed to delete old token", "email", email, "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	expiresAt := time.Now().Add(10 * time.Minute)
	token := &models.OneTimeToken{
		UserID:     &user.User.ID,
		TokenType:  types.OneTimeTokenTypeMagicLink,
		TokenHash:  tokenHash,
		RelatesTo:  email,
		Email:      &email,
		ExpiresAt:  &expiresAt,
		InstanceId: a.authService.GetInstanceId(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := authServiceImpl.GetOneTimeTokenService().Create(c.Request.Context(), token); err != nil {
		slog.Error("sendMagicLink: failed to store token", "email", email, "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	confirmationURL, err := magicLinkURL(redirectTo, plainToken)
	if err != nil {
		slog.Warn("sendMagicLink: invalid redirect URL", "redirect_to", redirectTo, "error", err)
		return consts.VALIDATION_FAILED
	}
	template, found := a.authService.GetMessageTemplate(a.authService.GetInstanceId(), "email", "magic-link")
	if !found {
		slog.Error("sendMagicLink: magic-link template not found")
		return consts.UNEXPECTED_FAILURE
	}
	rendered, err := template.Render(c.Request.Context(), map[string]interface{}{
		"ConfirmationURL": confirmationURL,
		"SiteURL":         a.authService.GetConfig().SiteURL,
		"Email":           email,
	})
	if err != nil {
		slog.Error("sendMagicLink: failed to render template", "error", err)
		return err
	}
	subject := ""
	if rendered.GetSubject() != nil {
		subject = *rendered.GetSubject()
	}
	messageID, err := emailProvider.SendEmail(c.Request.Context(), email, subject, rendered.GetBody())
	if err != nil {
		slog.Error("sendMagicLink: failed to send email", "email", email, "error", err)
		return err
	}

	resp := &SendOTPResponse{}
	if messageID != nil {
		resp.MessageID = *messageID
	}
	return c.Render(resp)
}

func magicLinkURL(redirectTo string, plainToken string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(redirectTo))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid redirect URL")
	}
	values := parsed.Query()
	values.Set("token", plainToken)
	values.Set("type", "magiclink")
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

// @Summary Send SMS Verification Code
// @Description Send verification code to user's phone number
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SendSMSOTPRequest true "SMS verification request"
// @Success 200 {object} SendSMSOTPResponse "SMS verification code sent successfully"
// @Router /sms-otp [post]
func (a *AuthController) SendSMSVerificationCode(c *pin.Context) error {
	req := &SendSMSOTPRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	slog.Info("SendSMSVerificationCode request received", "phone", req.Phone)

	if req.Phone == "" {
		return consts.VALIDATION_FAILED
	}

	normalizedPhone, ok := normalizePhone(req.Phone)
	if !ok {
		return consts.VALIDATION_FAILED
	}

	otpReq := &types.SendOTPRequest{
		Phone: normalizedPhone,
	}

	otpCtx := otp.NewOTPContext(c.Request.Context(), a.authService, c.Request, otpReq)

	chain := otp.CreateOTPChain(otpCtx)
	err := chain.Execute(otpCtx)
	if err != nil {
		slog.Error("Failed to send SMS verification code", "error", err, "phone", req.Phone)
		return consts.UNEXPECTED_FAILURE
	}

	slog.Info("SMS verification code sent successfully", "phone", req.Phone)

	resp := &SendSMSOTPResponse{
		MessageID:   otpCtx.Response().MessageID,
		SessionCode: otpCtx.Response().SessionCode,
	}

	return c.Render(resp)
}

// @Summary Verify Email Code
// @Description Verify email verification code
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body VerifyOtpRequest true "Email verification request"
// @Success 200 {object} SuccessResponse "Email verification successful"
// @Router /verify [post]
func (a *AuthController) VerifyEmailCode(c *pin.Context) error {
	req := &types.VerifyOtpRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	slog.Info("VerifyEmailCode request received", "email", req.Email, "token", req.Token)
	if isMagicLinkVerifyType(req.Type) {
		return a.verifyMagicLink(c, req)
	}
	if req.Phone != "" {
		normalizedPhone, ok := normalizePhone(req.Phone)
		if !ok {
			return consts.VALIDATION_FAILED
		}
		req.Phone = normalizedPhone
	}

	// Check token verification rate limit
	config := a.authService.GetConfig()
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if ok {
		rateLimitService := authServiceImpl.GetRateLimitService()
		// Use email or phone as userKey
		var userKey any = req.Email
		if req.Email == "" {
			userKey = req.Phone
		}

		allowed, err := rateLimitService.CheckAndRecordRequest(
			c.Request.Context(),
			userKey,
			"token_verification",
			a.authService.GetInstanceId(),
			config.RatelimitConfig.TokenVerificationRateLimit,
			config,
		)
		if err != nil {
			slog.Error("VerifyEmailCode: Rate limit check failed", "error", err)
			return err
		}
		if !allowed {
			slog.Warn("VerifyEmailCode: Rate limit exceeded", "email", req.Email, "phone", req.Phone)
			return consts.OVER_REQUEST_RATE_LIMIT
		}
	}

	if len(req.Token) != 6 {
		slog.Warn("Invalid verification code length", "email", req.Email, "token_length", len(req.Token))
		return consts.VALIDATION_FAILED
	}

	for _, char := range req.Token {
		if char < '0' || char > '9' {
			slog.Warn("Invalid verification code format", "email", req.Email, "token", req.Token)
			return consts.VALIDATION_FAILED
		}
	}

	if strings.TrimSpace(req.SessionCode) == "" {
		slog.Warn("Missing session code for OTP verification", "email", req.Email, "phone", req.Phone)
		return consts.VALIDATION_FAILED
	}

	db := a.authService.GetDB()
	instanceId := a.authService.GetInstanceId()
	otpService := authServiceImpl.GetOTPService()
	valid, err := otpService.VerifyOTP(c.Request.Context(), req.Email, req.Phone, req.Token, req.SessionCode, types.OneTimeTokenTypeConfirmation, instanceId, db)
	if err != nil || !valid {
		slog.Warn("OTP verification failed", "error", err, "email", req.Email, "phone", req.Phone)
		return consts.VALIDATION_FAILED
	}

	slog.Info("Email verification successful", "email", req.Email, "phone", req.Phone)

	if strings.TrimSpace(req.Phone) != "" {
		var userMetadata map[string]any
		if req.Options != nil {
			userMetadata = req.Options.Data
		}
		return a.createPhoneOTPSession(c, req.Phone, userMetadata)
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token := authHeader[7:]
		claims, err := a.authService.ValidateJWT(token)
		if err == nil {

			if sessionID, ok := claims["session_id"].(uint); ok {
				instanceId := a.authService.GetInstanceId()
				sessionService := services.NewSessionService(a.authService.GetDB())

				config := a.authService.GetConfig()
				aalTimeout := config.SecurityConfig.AALPolicy.AALTimeout
				now := time.Now()
				expiresAt := now.Add(aalTimeout)

				slog.Info("Setting AAL2 expiry time",
					"sessionID", sessionID,
					"aalTimeout", aalTimeout,
					"currentTime", now,
					"currentTimeUTC", now.UTC(),
					"currentTimeUnix", now.Unix(),
					"expiresAt", expiresAt,
					"expiresAtUTC", expiresAt.UTC(),
					"expiresAtUnix", expiresAt.Unix(),
				)

				err = sessionService.UpdateAALWithExpiry(c.Request.Context(), sessionID, instanceId, types.AALLevel2, &expiresAt)
				if err != nil {
					slog.Warn("Failed to upgrade AAL level", "sessionID", sessionID, "error", err)
				} else {
					slog.Info("AAL level upgraded to AAL2", "sessionID", sessionID, "expiresAt", expiresAt, "expiresAtUTC", expiresAt.UTC())
				}
			}
		}
	}

	resp := &SuccessResponse{
		Success: true,
	}

	return c.Render(resp)
}

func isMagicLinkVerifyType(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "magiclink" || normalized == "magic_link"
}

func (a *AuthController) verifyMagicLink(c *pin.Context, req *types.VerifyOtpRequest) error {
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if !ok {
		slog.Error("verifyMagicLink: invalid auth service type")
		return consts.UNEXPECTED_FAILURE
	}
	plainToken := strings.TrimSpace(req.Token)
	if plainToken == "" {
		return consts.VALIDATION_FAILED
	}

	tokenHash := services.HashToken(plainToken)
	stored, err := authServiceImpl.GetOneTimeTokenService().GetWithUser(c.Request.Context(), tokenHash, a.authService.GetInstanceId())
	if err != nil {
		slog.Warn("verifyMagicLink: token not found", "error", err)
		return consts.VALIDATION_FAILED
	}
	if stored.TokenType != types.OneTimeTokenTypeMagicLink {
		slog.Warn("verifyMagicLink: invalid token type", "type", stored.TokenType)
		return consts.VALIDATION_FAILED
	}
	if stored.ExpiresAt == nil || time.Now().After(*stored.ExpiresAt) {
		slog.Warn("verifyMagicLink: token expired", "token_id", stored.ID)
		return consts.VALIDATION_FAILED
	}
	if stored.User == nil {
		slog.Error("verifyMagicLink: token missing user", "token_id", stored.ID)
		return consts.UNEXPECTED_FAILURE
	}
	if stored.User.EmailConfirmedAt == nil {
		if err := authServiceImpl.GetUserService().ConfirmEmail(c.Request.Context(), stored.User.ID, a.authService.GetInstanceId()); err != nil {
			slog.Error("verifyMagicLink: failed to confirm email", "user_id", stored.User.ID, "error", err)
			return consts.UNEXPECTED_FAILURE
		}
		if err := authServiceImpl.GetDB().WithContext(c.Request.Context()).First(stored.User, stored.User.ID).Error; err != nil {
			slog.Error("verifyMagicLink: failed to reload confirmed user", "user_id", stored.User.ID, "error", err)
			return consts.UNEXPECTED_FAILURE
		}
	}

	email := ""
	if stored.User.Email != nil {
		email = *stored.User.Email
	}
	user, err := authServiceImpl.GetUserService().GetByEmail(c.Request.Context(), email)
	if err != nil {
		slog.Error("verifyMagicLink: failed to load user service wrapper", "user_id", stored.User.ID, "error", err)
		return consts.UNEXPECTED_FAILURE
	}
	session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(),
		user,
		types.AALLevel1,
		[]string{string(services.AuthMethodMagicLink)},
		c.GetHeader("User-Agent"),
		c.ClientIP(),
	)
	if err != nil {
		slog.Error("verifyMagicLink: session creation failed", "user_id", stored.User.ID, "error", err)
		return consts.UNEXPECTED_FAILURE
	}
	if err := authServiceImpl.GetOneTimeTokenService().DeleteByID(c.Request.Context(), stored.ID, a.authService.GetInstanceId()); err != nil {
		slog.Warn("verifyMagicLink: failed to delete used token", "token_id", stored.ID, "error", err)
	}

	userData := convertUserToResponse(a.authService, stored.User)
	expiresIn := int(expiresAt - time.Now().Unix())
	if expiresIn < 0 {
		expiresIn = 0
	}
	sessionData := &Session{
		ID:           session.HashID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		User:         userData,
	}
	return c.Render(&AuthData{
		User:    userData,
		Session: sessionData,
	})
}

func (a *AuthController) createPhoneOTPSession(c *pin.Context, phone string, userMetadata map[string]any) error {
	user, err := a.authService.GetUserService().GetOrCreatePhoneOTPUser(c.Request.Context(), phone, userMetadata)
	if err != nil {
		slog.Error("Phone OTP user lookup/create failed", "error", err, "phone", phone)
		return consts.UNEXPECTED_FAILURE
	}

	session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(), user, types.AALLevel1, []string{"sms"},
		c.GetHeader("User-Agent"), c.ClientIP(),
	)
	if err != nil {
		slog.Error("Phone OTP session creation failed", "error", err, "phone", phone)
		return consts.UNEXPECTED_FAILURE
	}

	userData := convertUserToResponse(a.authService, user.GetModel())
	expiresIn := int(expiresAt - time.Now().Unix())
	if expiresIn < 0 {
		expiresIn = 0
	}
	sessionData := &Session{
		ID:           session.HashID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		User:         userData,
	}

	return c.Render(&AuthData{
		User:    userData,
		Session: sessionData,
	})
}

// isValidEmail validates email format
func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func normalizePhone(phone string) (string, bool) {
	// Remove spaces and common separators
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")

	if phone == "" {
		return "", false
	}

	// Accept E.164 directly
	e164Regex := regexp.MustCompile(`^\+[1-9]\d{9,14}$`)
	if e164Regex.MatchString(phone) {
		return phone, true
	}

	// Auto-prefix China mobile numbers without "+"
	cnRegex := regexp.MustCompile(`^1\d{10}$`)
	if cnRegex.MatchString(phone) {
		return "+1" + phone, true
	}

	return "", false
}
