package controller

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// MFAController handles multi-factor authentication operations
type MFAController struct {
	authService services.AuthService
}

// ===== Request/Response Types =====

// MFAEnrollRequest represents MFA factor enrollment request
// @Description Request to enroll a new MFA factor
type MFAEnrollRequest struct {
	FactorType   types.FactorType `json:"factorType" example:"totp" description:"Type of MFA factor (totp, phone)"`
	Issuer       string           `json:"issuer,omitempty" example:"MyApp" description:"Issuer name for TOTP"`
	FriendlyName string           `json:"friendlyName,omitempty" example:"My Phone" description:"User-friendly name for the factor"`
	Phone        string           `json:"phone,omitempty" example:"+1234567890" description:"Phone number for phone factors"`
}

// MFAEnrollData represents MFA factor enrollment response
// @Description Response data for MFA factor enrollment
type MFAEnrollData struct {
	ID           string           `json:"id" example:"factor_123" description:"Factor identifier"`
	Type         types.FactorType `json:"type" example:"totp" description:"Factor type"`
	FriendlyName string           `json:"friendly_name,omitempty" example:"My Phone" description:"User-friendly name"`
	Phone        string           `json:"phone,omitempty" example:"+1234567890" description:"Phone number (for phone factors)"`
	TOTP         *TOTPEnrollData  `json:"totp,omitempty" description:"TOTP enrollment data (for TOTP factors)"`
	WebAuthn     *WebAuthnEnroll  `json:"webauthn,omitempty" description:"WebAuthn enrollment data (for WebAuthn factors)"`
}

type TOTPEnrollData struct {
	QRCode string `json:"qr_code"`
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type WebAuthnEnroll struct {
	ChallengeID     string          `json:"challenge_id"`
	CreationOptions json.RawMessage `json:"creation_options"`
}

type MFAChallengeRequest struct {
	FactorID   string           `json:"factorId,omitempty"`
	FactorType types.FactorType `json:"factorType,omitempty"`
	Identifier string           `json:"identifier,omitempty"` // phone/email/username
	Channel    string           `json:"channel,omitempty"`    // sms, whatsapp (for phone factors)
}

type MFAChallengeData struct {
	ID        string           `json:"id"`
	Type      types.FactorType `json:"type"`
	ExpiresAt int64            `json:"expires_at"`
}

// MFAVerifyRequest represents MFA verification request
// @Description Request to verify MFA challenge
type MFAVerifyRequest struct {
	FactorID    string          `json:"factorId" example:"factor_123" description:"MFA factor identifier"`
	ChallengeID string          `json:"challengeId" example:"challenge_456" description:"Challenge identifier"`
	Code        string          `json:"code" example:"123456" description:"Verification code"`
	Credential  json.RawMessage `json:"credential,omitempty" swaggertype:"object,string"`
}

type MFAVerifyData struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	User         *User  `json:"user,omitempty"`
}

type MFAUnenrollRequest struct {
	FactorID string `json:"factorId"`
}

type MFAUnenrollData struct {
	ID string `json:"id"`
}

type MFAListFactorsData struct {
	All   []Factor `json:"all"`
	TOTP  []Factor `json:"totp"`
	Phone []Factor `json:"phone"`
}

type MFAChallengeAndVerifyRequest struct {
	FactorID string `json:"factorId"`
	Code     string `json:"code"`
}

type MFAAssuranceLevelData struct {
	CurrentLevel                 types.AALLevel `json:"currentLevel"`
	NextLevel                    types.AALLevel `json:"nextLevel"`
	CurrentAuthenticationMethods []AMREntry     `json:"currentAuthenticationMethods"`
}

type AMREntry struct {
	Method    string `json:"method"` // password, otp, oauth, mfa/totp
	Timestamp int64  `json:"timestamp"`
}

// ===== Controller Methods =====

// Enroll starts MFA factor enrollment
// @Summary Enroll MFA Factor
// @Description Enroll a new multi-factor authentication factor
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MFAEnrollRequest true "MFA enrollment request"
// @Success 200 {object} MFAEnrollData "MFA factor enrolled successfully"
// @Router /factors/enroll [post]
func (m *MFAController) Enroll(c *pin.Context) error {
	var req MFAEnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return c.RenderError(err)
	}

	if req.FactorType == types.FactorTypeWebAuthn {
		user, err := m.getCurrentUser(c)
		if err != nil {
			return c.RenderError(err)
		}

		rp, err := m.getWebAuthnRPConfig()
		if err != nil {
			return c.RenderError(err)
		}

		engine, err := services.NewGoWebAuthnEngine(rp)
		if err != nil {
			return c.RenderError(err)
		}
		webauthnSvc := services.NewWebAuthnService(m.authService, engine)

		ip := ""
		if c.Context != nil {
			ip = c.Context.ClientIP()
		}

		begin, err := webauthnSvc.BeginRegistration(c.Request.Context(), rp, user, req.FriendlyName, ip)
		if err != nil {
			return c.RenderError(err)
		}

		return c.Render(&MFAEnrollData{
			ID:           begin.FactorID,
			Type:         types.FactorTypeWebAuthn,
			FriendlyName: req.FriendlyName,
			WebAuthn: &WebAuthnEnroll{
				ChallengeID:     begin.ChallengeID,
				CreationOptions: begin.CreationOptions,
			},
		})
	}

	// Get current user
	user, err := m.getCurrentUser(c)
	if err != nil {
		return c.RenderError(err)
	}

	// Get MFA Provider
	provider, exists := m.authService.GetMFAProvider(string(req.FactorType))
	if !exists {
		return c.RenderError(consts.PROVIDER_DISABLED)
	}

	// Call Provider's Enroll method to generate secret
	secret, err := provider.Enroll(c.Request.Context(), req.FactorType, req.Issuer, req.FriendlyName, req.Phone)
	if err != nil {
		return c.RenderError(err)
	}

	// Save MFA factor to database
	factor, err := user.EnrollMFAFactor(c.Request.Context(), req.FactorType, req.FriendlyName, secret, req.Phone)
	if err != nil {
		return c.RenderError(err)
	}

	// Generate hashid
	factorHashID, err := services.GenerateUserHashID(factor.ID)
	if err != nil {
		return c.RenderError(err)
	}

	// Debug log
	fmt.Printf("DEBUG: Created MFA factor with ID: %d, HashID: %s, Type: %s, Status: %s\n",
		factor.ID, factorHashID, factor.FactorType, factor.Status)

	// Build response data
	enrollData := &MFAEnrollData{
		ID:           factorHashID,
		Type:         req.FactorType,
		FriendlyName: req.FriendlyName,
		Phone:        req.Phone,
	}

	// If TOTP, add TOTP-specific data
	if req.FactorType == "totp" {

		issuer := req.Issuer
		if issuer == "" {
			issuer = "slauth"
		}

		totpURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
			issuer, user.GetEmail(), secret, issuer)

		enrollData.TOTP = &TOTPEnrollData{
			QRCode: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==",
			Secret: secret,
			URI:    totpURI,
		}
	}

	return c.Render(enrollData)
}

// Challenge creates MFA challenge
// @Summary Create MFA Challenge
// @Description Create a challenge for MFA verification
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Param factorId path string true "MFA Factor ID"
// @Success 200 {object} MFAChallengeData "Challenge created successfully"
// @Router /factors/challenge [post]
func (m *MFAController) Challenge(c *pin.Context) error {
	var req MFAChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return c.RenderError(err)
	}

	// WebAuthn login is anonymous: identifier -> allowCredentials -> requestOptions
	if req.FactorType == types.FactorTypeWebAuthn || req.Identifier != "" {
		if req.Identifier == "" {
			return c.RenderError(consts.VALIDATION_FAILED)
		}

		rp, err := m.getWebAuthnRPConfig()
		if err != nil {
			return c.RenderError(err)
		}

		engine, err := services.NewGoWebAuthnEngine(rp)
		if err != nil {
			return c.RenderError(err)
		}
		webauthnSvc := services.NewWebAuthnService(m.authService, engine)

		ip := ""
		if c.Context != nil {
			ip = c.Context.ClientIP()
		}

		res, err := webauthnSvc.BeginAuthentication(c.Request.Context(), rp, req.Identifier, ip)
		if err != nil {
			return c.RenderError(err)
		}
		return c.Render(res)
	}

	return c.Render(&MFAChallengeData{})
}

// Verify verifies MFA challenge
// @Summary Verify MFA Challenge
// @Description Verify MFA challenge with provided code
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param factorId path string true "MFA Factor ID"
// @Param request body MFAVerifyRequest true "MFA verification request"
// @Success 200 {object} MFAVerifyData "MFA verification successful"
// @Router /factors/verify [post]
func (m *MFAController) Verify(c *pin.Context) error {
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return c.RenderError(err)
	}

	// WebAuthn verify can be anonymous (login) or authenticated (finish enrollment).
	if len(req.Credential) > 0 {
		rp, err := m.getWebAuthnRPConfig()
		if err != nil {
			return c.RenderError(err)
		}

		engine, err := services.NewGoWebAuthnEngine(rp)
		if err != nil {
			return c.RenderError(err)
		}
		webauthnSvc := services.NewWebAuthnService(m.authService, engine)

		hasAuth := c.GetHeader("Authorization") != ""

		if hasAuth {
			_, err := m.getCurrentUser(c)
			if err != nil {
				return c.RenderError(err)
			}

			res, err := webauthnSvc.FinishRegistration(c.Request.Context(), rp, req.ChallengeID, req.Credential)
			if err != nil {
				return c.RenderError(err)
			}
			return c.Render(res)
		}

		ip := ""
		if c.Context != nil {
			ip = c.Context.ClientIP()
		}
		ua := ""
		if c.Request != nil {
			ua = c.Request.UserAgent()
		}

		res, err := webauthnSvc.FinishAuthentication(c.Request.Context(), rp, req.ChallengeID, req.Credential, ua, ip)
		if err != nil {
			return c.RenderError(err)
		}

		userObj, err := m.authService.GetUserService().GetByHashID(c.Request.Context(), res.UserID)
		if err != nil {
			return c.RenderError(err)
		}
		userData := convertUserToResponse(userObj.User)

		sessionData := &Session{
			ID:           res.SessionID,
			AccessToken:  res.AccessToken,
			RefreshToken: res.RefreshToken,
			ExpiresIn:    res.ExpiresIn,
			ExpiresAt:    res.ExpiresAt,
			TokenType:    res.TokenType,
			User:         userData,
		}

		return c.Render(&AuthData{
			User:    userData,
			Session: sessionData,
		})
	}

	// Get current user
	user, err := m.getCurrentUser(c)
	if err != nil {
		return c.RenderError(err)
	}

	// Parse factorID (hashid)
	factorID := req.FactorID
	realFactorID, err := services.GetUserIDFromHashID(factorID)
	if err != nil {
		return c.RenderError(consts.INVALID_CREDENTIALS)
	}

	// Get MFA factor
	factor, err := user.GetMFAFactor(c.Request.Context(), realFactorID)
	if err != nil {
		return c.RenderError(consts.INVALID_CREDENTIALS)
	}

	// Get corresponding MFA Provider
	provider, exists := m.authService.GetMFAProvider(string(factor.FactorType))
	if !exists {
		return c.RenderError(consts.PROVIDER_DISABLED)
	}

	// Call Provider's Verify method
	_, err = provider.Verify(c.Request.Context(), req.FactorID, req.ChallengeID, req.Code)
	if err != nil {
		return c.RenderError(consts.MFA_VERIFICATION_FAILED)
	}

	// Verification successful, update factor status to verified
	err = user.VerifyMFAFactor(c.Request.Context(), realFactorID)
	if err != nil {
		return c.RenderError(err)
	}

	// Build response data - simply return success status
	verifyData := &MFAVerifyData{
		AccessToken:  "verified",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "verified",
		User: &User{
			ID:        user.HashID,
			Email:     user.GetEmail(),
			CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}

	return c.Render(verifyData)
}

// Unenroll removes MFA factor
// @Summary Unenroll MFA Factor
// @Description Remove an enrolled MFA factor
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Param factorId path string true "MFA Factor ID"
// @Success 200 {object} MFAUnenrollData "MFA factor unenrolled successfully"
// @Router /factors/{factor_id} [delete]
func (m *MFAController) Unenroll(c *pin.Context) error {
	return c.Render(&MFAUnenrollData{})
}

// ListFactors returns user's MFA factors
// @Summary List MFA Factors
// @Description Get list of user's enrolled MFA factors
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} MFAListFactorsData "MFA factors retrieved successfully"
// @Router /factors [get]
func (m *MFAController) ListFactors(c *pin.Context) error {
	// Get current user
	user, err := m.getCurrentUser(c)
	if err != nil {
		return c.RenderError(err)
	}

	// Get user's MFA factors from database
	factors, err := user.ListMFAFactors(c.Request.Context())
	if err != nil {
		return c.RenderError(err)
	}

	// Convert to response format
	var allFactors []Factor
	var totpFactors []Factor
	var phoneFactors []Factor

	for _, factor := range factors {
		// Generate hashid
		factorHashID, err := services.GenerateUserHashID(factor.ID)
		if err != nil {
			return c.RenderError(err)
		}

		f := Factor{
			ID:         factorHashID,
			FactorType: factor.FactorType,
			Status:     factor.Status,
			CreatedAt:  factor.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:  factor.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}

		if factor.FriendlyName != nil {
			f.FriendlyName = *factor.FriendlyName
		}

		allFactors = append(allFactors, f)

		// Classify by type
		switch factor.FactorType {
		case types.FactorTypeTOTP:
			totpFactors = append(totpFactors, f)
		case types.FactorTypePhone:
			phoneFactors = append(phoneFactors, f)
		}
	}

	factorsData := &MFAListFactorsData{
		All:   allFactors,
		TOTP:  totpFactors,
		Phone: phoneFactors,
	}

	return c.Render(factorsData)
}

// ChallengeAndVerify combines challenge and verify in one call
// POST /factors/{factorId}/challenge-and-verify
func (m *MFAController) ChallengeAndVerify(c *pin.Context) error {
	return c.Render(&MFAVerifyData{})
}

// GetAuthenticatorAssuranceLevel returns current AAL
// GET /aal
func (m *MFAController) GetAuthenticatorAssuranceLevel(c *pin.Context) error {
	return c.Render(&MFAAssuranceLevelData{})
}

// getCurrentUser Get current user object
func (m *MFAController) getCurrentUser(c *pin.Context) (*services.User, error) {
	// Get token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, consts.NO_AUTHORIZATION
	}

	// Remove "Bearer " prefix
	token := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	// Validate JWT token
	claims, err := m.authService.ValidateJWT(token)
	if err != nil {
		return nil, consts.BAD_JWT
	}

	// Get user ID from claims (hashid)
	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, consts.BAD_JWT
	}

	// Get user object
	user, err := m.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return nil, consts.USER_NOT_FOUND
	}

	return user, nil
}

func (m *MFAController) getWebAuthnRPConfig() (services.WebAuthnRPConfig, error) {
	cfg := m.authService.GetConfig()
	if cfg == nil || cfg.SiteURL == "" {
		return services.WebAuthnRPConfig{}, consts.VALIDATION_FAILED
	}
	u, err := url.Parse(cfg.SiteURL)
	if err != nil || u.Hostname() == "" {
		return services.WebAuthnRPConfig{}, consts.VALIDATION_FAILED
	}
	origin := u.Scheme + "://" + u.Host
	return services.WebAuthnRPConfig{
		RPID:          u.Hostname(),
		RPDisplayName: "slauth",
		RPOrigins:     []string{origin},
	}, nil
}
