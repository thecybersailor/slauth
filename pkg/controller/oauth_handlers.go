package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/flaboy/pin"
	"github.com/speps/go-hashids/v2"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/providers/identities/saml"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// hashid configuration for flow IDs
var (
	hashidData *hashids.HashIDData
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const httpRequestContextKey contextKey = "http_request"

func init() {
	hd := hashids.NewData()
	hd.Salt = "@cybersailor/slauth-ts-flow-salt"
	hd.MinLength = 20
	hashidData = hd
}

// encodeFlowID encodes database ID to hashid
func encodeFlowID(id uint) (string, error) {
	h, err := hashids.NewWithData(hashidData)
	if err != nil {
		return "", err
	}
	return h.Encode([]int{int(id)})
}

// decodeFlowID decodes hashid to database ID
func decodeFlowID(hashid string) (uint, error) {
	h, err := hashids.NewWithData(hashidData)
	if err != nil {
		return 0, err
	}
	ids, err := h.DecodeWithError(hashid)
	if err != nil {
		return 0, err
	}
	if len(ids) != 1 {
		return 0, consts.VALIDATION_FAILED
	}
	return uint(ids[0]), nil
}

// SignInWithOAuth initiates OAuth authentication flow
// @Summary OAuth Login
// @Description Initiate OAuth authentication flow with external provider
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SignInWithOAuthRequest true "OAuth login request"
// @Success 200 {object} OAuthData "OAuth flow initiated successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 422 {object} map[string]interface{} "Provider disabled"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /authorize [post]
func (a *AuthController) SignInWithOAuth(c *pin.Context) error {
	req := &SignInWithOAuthRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Debug: Print request details
	slog.Info("OAuth request", "provider", req.Provider, "redirect_to", req.RedirectTo, "options", req.Options)

	// Validate provider
	if req.Provider == "" {
		return consts.VALIDATION_FAILED
	}

	// Get the identity provider
	provider, exists := getIdentityProvider(a.authService, req.Provider)
	if !exists {
		return consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}

	oauthConfig, err := provider.Authorize(req.Options)
	if err != nil {
		return consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}

	if oauthConfig == nil {

		return c.Render(&OAuthData{
			Provider: req.Provider,
			Config:   nil,
		})
	}

	switch oauthConfig.FlowType {
	case types.FlowTypeIDToken, types.FlowTypeHybrid:
		return c.Render(&OAuthData{
			Provider: req.Provider,
			Config:   oauthConfig.Config,
		})

	case types.FlowTypeAuthCode:

		flowID, err := a.createOAuthFlowState(c, provider, req.Options, req.RedirectTo)
		if err != nil {
			return consts.OAUTH_PROVIDER_NOT_SUPPORTED
		}

		return c.Render(&OAuthData{
			Provider: req.Provider,
			Config:   oauthConfig.Config,
			FlowID:   flowID,
		})

	default:
		return consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}
}

// createOAuthFlowState creates OAuth flow state and returns flow ID
func (a *AuthController) createOAuthFlowState(c *pin.Context, provider types.IdentityProvider, options json.RawMessage, redirectTo string) (string, error) {
	// Generate PKCE parameters
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", err
	}

	codeChallenge := generateCodeChallenge(codeVerifier)
	state, err := generateSecureState()
	if err != nil {
		return "", err
	}

	// Parse options to get redirect_uri
	var opts struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if len(options) > 0 {
		if err := json.Unmarshal(options, &opts); err != nil {
			return "", err
		}
	}

	// Create flow state record for tracking
	flowState := &models.FlowState{
		AuthCode:             state,
		CodeChallengeMethod:  "S256",
		CodeChallenge:        codeChallenge,
		CodeVerifier:         codeVerifier,
		ProviderType:         provider.GetName(),
		RedirectURI:          opts.RedirectURI,
		RedirectTo:           redirectTo,
		AuthenticationMethod: "oauth",
		InstanceId:           a.authService.GetInstanceId(),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Save flow state to database
	if err := a.authService.CreateFlowState(c.Request.Context(), flowState); err != nil {
		return "", err
	}

	// Debug: Check if ID was set correctly
	slog.Info("FlowState created",
		"id", flowState.ID,
		"provider", flowState.ProviderType,
		"redirectURI", flowState.RedirectURI,
		"redirectTo", flowState.RedirectTo)

	// Return flow ID (using hashid) - ID is now set after CreateFlowState
	flowID, err := encodeFlowID(flowState.ID)
	if err != nil {
		slog.Error("Failed to encode flow ID", "error", err, "id", flowState.ID)
		return "", err
	}

	slog.Info("FlowID encoded", "flowID", flowID, "originalID", flowState.ID)
	return flowID, nil
}

// ExchangeCodeForSession exchanges OAuth code for session (PKCE flow)
// @Summary Exchange OAuth Code
// @Description Exchange OAuth authorization code for access token (PKCE flow)
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ExchangeCodeRequest true "Code exchange request"
// @Success 200 {object} AuthData "Code exchanged successfully"
// @Router /token [post]
func (a *AuthController) ExchangeCodeForSession(c *pin.Context) error {
	req := &ExchangeCodeRequest{}
	if err := c.BindJSON(req); err != nil {
		slog.Error("Failed to bind JSON", "error", err)
		return consts.BAD_JSON
	}

	// Debug: Print request details
	slog.Info("PKCE exchange request", "auth_code", req.AuthCode, "code_verifier", req.CodeVerifier, "flow_id", req.FlowID)

	// Validate required fields
	if req.AuthCode == "" {
		slog.Error("AuthCode is empty")
		return consts.VALIDATION_FAILED
	}

	// Validate flow_id is required
	if req.FlowID == "" {
		slog.Error("FlowID is empty")
		return consts.VALIDATION_FAILED
	}

	// Decode hashid to database ID
	slog.Info("Decoding flow ID", "hashid", req.FlowID)
	flowID, err := decodeFlowID(req.FlowID)
	if err != nil {
		slog.Error("Failed to decode flow ID", "error", err, "hashid", req.FlowID)
		return consts.VALIDATION_FAILED
	}
	slog.Info("Flow ID decoded", "hashid", req.FlowID, "decodedID", flowID)

	// Get flow state from database by ID
	flowState, err := a.authService.GetFlowStateByID(c.Request.Context(), flowID)
	if err != nil {
		return consts.FLOW_STATE_NOT_FOUND
	}

	// Update flow state with authorization code
	flowState.AuthCode = req.AuthCode
	flowState.AuthCodeIssuedAt = &[]time.Time{time.Now()}[0]
	if err := a.authService.UpdateFlowState(c.Request.Context(), flowState); err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Verify PKCE code challenge using stored code_verifier
	expectedChallenge := generateCodeChallenge(flowState.CodeVerifier)
	if expectedChallenge != flowState.CodeChallenge {
		return consts.BAD_CODE_VERIFIER
	}

	// Get the identity provider
	slog.Info("Getting identity provider", "providerType", flowState.ProviderType)
	provider, exists := getIdentityProvider(a.authService, flowState.ProviderType)
	if !exists {
		slog.Error("Identity provider not found", "providerType", flowState.ProviderType)
		return consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}
	slog.Info("Identity provider found", "providerName", provider.GetName())

	// Exchange authorization code for access token using provider
	authCodeLog := req.AuthCode
	if len(authCodeLog) > 20 {
		authCodeLog = authCodeLog[:20] + "..."
	}
	slog.Info("Calling ExchangeCodeForToken",
		"authCode", authCodeLog,
		"redirectURI", flowState.RedirectURI)
	oauthResp, err := provider.ExchangeCodeForToken(c.Request.Context(), req.AuthCode, flowState.RedirectURI)
	if err != nil {
		slog.Error("ExchangeCodeForToken failed", "error", err)
		return consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}
	slog.Info("ExchangeCodeForToken succeeded")

	// Convert ExternalUserInfo to OAuthUserInfo
	oauthUserInfo := &OAuthUserInfo{
		ID:       oauthResp.UserInfo.UID,
		Email:    oauthResp.UserInfo.Email,
		Name:     oauthResp.UserInfo.Name,
		Picture:  oauthResp.UserInfo.Avatar,
		Verified: true,
	}

	// Create or find user account (pass httpRequest in context for hooks)
	ctx := context.WithValue(c.Request.Context(), httpRequestContextKey, c.Request)
	user, err := a.findOrCreateUserFromOAuth(ctx, oauthUserInfo, flowState.ProviderType)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Create session
	slog.Info("[OAuth ExchangeCodeForSession] Before CreateSession", "userID", user.ID, "userIsNil", user == nil)
	session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(), user, "aal1", []string{"oauth"},
		c.GetHeader("User-Agent"), c.ClientIP(),
	)
	if err != nil {
		slog.Error("[OAuth ExchangeCodeForSession] CreateSession failed", "error", err)
		return consts.UNEXPECTED_FAILURE
	}
	sessionHashID := "nil"
	if session != nil {
		sessionHashID = session.HashID
	}
	slog.Info("[OAuth ExchangeCodeForSession] After CreateSession",
		"sessionIsNil", session == nil,
		"sessionHashID", sessionHashID,
		"accessTokenLen", len(accessToken),
		"refreshTokenLen", len(refreshToken),
		"expiresAt", expiresAt)

	// Trigger AuthenticatedUse middleware
	slog.Info("[OAuth ExchangeCodeForSession] Before ExecuteAuthenticatedMiddlewares")
	if authServiceImpl, ok := a.authService.(*services.AuthServiceImpl); ok {
		if err := authServiceImpl.ExecuteAuthenticatedMiddlewares(
			c.Request.Context(),
			user,
			session,
			services.AuthMethodOAuth,
			flowState.ProviderType,
			c.Request,
		); err != nil {
			slog.Error("AuthenticatedUse middleware failed", "error", err)
			// Don't fail the request, just log the error
		}
	}
	slog.Info("[OAuth ExchangeCodeForSession] After ExecuteAuthenticatedMiddlewares")

	// Clean up flow state
	slog.Info("[OAuth ExchangeCodeForSession] Before DeleteFlowState", "flowStateID", flowState.ID)
	if err := a.authService.DeleteFlowState(c.Request.Context(), flowState.ID); err != nil {
		slog.Error("Failed to delete flow state", "error", err, "flowStateID", flowState.ID)
		return consts.UNEXPECTED_FAILURE
	}
	slog.Info("[OAuth ExchangeCodeForSession] After DeleteFlowState", "flowStateID", flowState.ID)

	// Convert user to response format
	userGetModelIsNil := true
	if user != nil {
		userGetModelIsNil = user.GetModel() == nil
	}
	slog.Info("[OAuth ExchangeCodeForSession] Before convertUserToResponse",
		"userIsNil", user == nil,
		"userGetModelIsNil", userGetModelIsNil)
	userModel := user.GetModel()
	userModelID := uint(0)
	identitiesLen := -1
	mfaFactorsLen := -1
	if userModel != nil {
		userModelID = userModel.ID
		identitiesLen = len(userModel.Identities)
		mfaFactorsLen = len(userModel.MFAFactors)
	}
	slog.Info("[OAuth ExchangeCodeForSession] Got user model",
		"userModelIsNil", userModel == nil,
		"userModelID", userModelID,
		"identitiesLen", identitiesLen,
		"mfaFactorsLen", mfaFactorsLen)
	userResp := convertUserToResponse(a.authService, userModel)
	userRespID := "nil"
	if userResp != nil {
		userRespID = userResp.ID
	}
	slog.Info("[OAuth ExchangeCodeForSession] After convertUserToResponse",
		"userRespIsNil", userResp == nil,
		"userRespID", userRespID)

	// Calculate expires_in from expires_at
	expiresIn := int(expiresAt - time.Now().Unix())
	if expiresIn < 0 {
		expiresIn = 0
	}

	// Create session response
	oauthRespTokenInfoIsNil := true
	if oauthResp != nil {
		oauthRespTokenInfoIsNil = oauthResp.TokenInfo == nil
	}
	slog.Info("[OAuth ExchangeCodeForSession] Before creating sessionResp",
		"oauthRespIsNil", oauthResp == nil,
		"oauthRespTokenInfoIsNil", oauthRespTokenInfoIsNil)
	sessionResp := &Session{
		ID:                   session.HashID,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		ExpiresIn:            expiresIn,
		ExpiresAt:            expiresAt,
		TokenType:            "Bearer",
		ProviderToken:        oauthResp.TokenInfo.AccessToken,
		ProviderRefreshToken: oauthResp.TokenInfo.RefreshToken,
		User:                 userResp,
	}
	slog.Info("[OAuth ExchangeCodeForSession] After creating sessionResp",
		"sessionRespID", sessionResp.ID,
		"providerTokenLen", len(sessionResp.ProviderToken),
		"providerRefreshTokenLen", len(sessionResp.ProviderRefreshToken))

	// Validate redirect URL from flow state
	redirectTo := ""
	if flowState.RedirectTo != "" {
		slog.Info("[OAuth ExchangeCodeForSession] Before ValidateAndGetRedirectTo", "redirectTo", flowState.RedirectTo)
		redirectService := a.createRedirectService()
		redirectTo = redirectService.ValidateAndGetRedirectTo(flowState.RedirectTo)
		slog.Info("OAuth: Redirect URL validated", "original", flowState.RedirectTo, "validated", redirectTo)
	}

	slog.Info("[OAuth ExchangeCodeForSession] Before creating AuthData response")
	resp := &AuthData{
		User:       userResp,
		Session:    sessionResp,
		RedirectTo: redirectTo,
	}
	slog.Info("[OAuth ExchangeCodeForSession] After creating AuthData response",
		"respUserIsNil", resp.User == nil,
		"respSessionIsNil", resp.Session == nil)

	slog.Info("[OAuth ExchangeCodeForSession] Before c.Render")
	err = c.Render(resp)
	if err != nil {
		slog.Error("[OAuth ExchangeCodeForSession] c.Render failed", "error", err)
		return err
	}
	slog.Info("[OAuth ExchangeCodeForSession] After c.Render - SUCCESS")
	return nil
}

// SignInWithIdToken authenticates using OIDC ID token (Google Button way)
// @Summary ID Token Login
// @Description Authenticate using OIDC ID token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SignInWithIdTokenRequest true "ID token login request"
// @Success 200 {object} AuthData "ID token authentication successful"
// @Router /token [post]
func (a *AuthController) SignInWithIdToken(c *pin.Context) error {
	req := &SignInWithIdTokenRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	slog.Info("SignInWithIdToken", "provider", req.Provider, "credential", string(req.Credential))

	// Validate required fields
	if req.Provider == "" {
		return consts.VALIDATION_FAILED
	}

	if len(req.Credential) == 0 {
		return consts.VALIDATION_FAILED
	}

	// Get the identity provider
	provider, exists := getIdentityProvider(a.authService, req.Provider)
	if !exists {
		return consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}

	// Validate ID token using the provider's implementation

	userInfo, err := provider.ValidateCredential(c.Request.Context(), req.Credential)
	if err != nil {
		return consts.BAD_JWT
	}

	if userInfo.UserInfo == nil {
		return consts.BAD_JWT
	}

	// Convert ExternalUserInfo to OAuthUserInfo
	oauthUserInfo := &OAuthUserInfo{
		ID:       userInfo.UserInfo.UID,
		Email:    userInfo.UserInfo.Email,
		Name:     userInfo.UserInfo.Name,
		Picture:  userInfo.UserInfo.Avatar,
		Verified: true,
	}

	// Create or find user account
	ctx := context.WithValue(c.Request.Context(), httpRequestContextKey, c.Request)
	user, err := a.findOrCreateUserFromOAuth(ctx, oauthUserInfo, req.Provider)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Create session
	session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(), user, "aal1", []string{"id_token"},
		c.GetHeader("User-Agent"), c.ClientIP(),
	)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Convert user to response format
	userResp := convertUserToResponse(a.authService, user.GetModel())

	// Calculate expires_in from expires_at
	expiresIn := int(expiresAt - time.Now().Unix())
	if expiresIn < 0 {
		expiresIn = 0
	}

	// Create session response
	sessionResp := &Session{
		ID:           session.HashID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
		User:         userResp,
	}

	resp := &AuthData{
		User:    userResp,
		Session: sessionResp,
	}

	return c.Render(resp)
}

// SignInWithSSO initiates SSO authentication
// @Summary SSO Login
// @Description Initiate SSO authentication with SAML provider
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body SignInWithSSORequest true "SSO login request"
// @Success 200 {object} SSOData "SSO authentication initiated successfully"
// @Router /sso [post]
func (a *AuthController) SignInWithSSO(c *pin.Context) error {
	req := &SignInWithSSORequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate instance or provider ID
	if req.Instance == "" && req.ProviderId == "" {
		return consts.VALIDATION_FAILED
	}

	// Create SAML service
	samlService := services.NewSAMLService(a.authService.GetDB(), a.authService.GetInstanceId())

	// Find SSO provider
	var ssoProvider *services.SSOProvider
	var err error

	if req.Instance != "" {
		ssoProvider, err = samlService.FindSSOProviderByInstance(c.Request.Context(), req.Instance)
	} else {
		ssoProvider, err = samlService.FindSSOProviderByID(c.Request.Context(), req.ProviderId)
	}

	if err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	// Get SAML configuration
	samlConfig, err := samlService.GetSAMLProvider(c.Request.Context(), ssoProvider)
	if err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	// Create certificate service (using default paths for now)
	certService := saml.NewCertService("./files/saml.crt", "./files/saml.key")

	// Create SAML provider instance
	samlProvider, err := samlService.CreateSAMLProvider(c.Request.Context(), samlConfig, certService)
	if err != nil {
		slog.Error("Failed to create SAML provider", "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	// Generate SAML AuthnRequest
	options := map[string]interface{}{}
	if req.Options != nil {
		if req.Options.RedirectTo != "" {
			options["redirect_to"] = req.Options.RedirectTo
		}
	}

	optionsJSON, _ := json.Marshal(options)
	oauthConfig, err := samlProvider.Authorize(optionsJSON)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Generate unique request ID for relay state
	requestID, err := generateSecureState()
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Create relay state
	relayOptions := &services.SAMLRelayStateOptions{}
	if req.Options != nil {
		relayOptions.RedirectTo = &req.Options.RedirectTo
	}

	_, err = samlService.CreateRelayState(c.Request.Context(), ssoProvider.ID, requestID, relayOptions)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Build SSO URL with relay state
	ssoURL := oauthConfig.Config.(map[string]any)["sso_url"].(string)
	ssoURL += "?RelayState=" + requestID

	resp := &SSOData{
		URL: ssoURL,
	}

	return c.Render(resp)
}

// HandleSSOCallback handles SSO provider callback
// @Summary SSO Callback
// @Description Handle SSO provider callback with SAML response
// @Tags Auth
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param SAMLResponse formData string true "SAML response from provider"
// @Param RelayState formData string true "Relay state parameter"
// @Success 200 {object} AuthData "SSO callback processed successfully"
// @Router /sso/callback [post]
func (a *AuthController) HandleSSOCallback(c *pin.Context) error {
	// Get SAML Response from POST form
	samlResponse := c.PostForm("SAMLResponse")
	relayState := c.PostForm("RelayState")

	if samlResponse == "" {
		return consts.VALIDATION_FAILED
	}

	if relayState == "" {
		return consts.SAML_RELAY_STATE_NOT_FOUND
	}

	// Create SAML service
	samlService := services.NewSAMLService(a.authService.GetDB(), a.authService.GetInstanceId())

	// Get relay state information
	relayStateObj, err := samlService.GetRelayState(c.Request.Context(), relayState)
	if err != nil {
		return consts.SAML_RELAY_STATE_NOT_FOUND
	}

	// Find SSO provider
	var ssoProvider models.SSOProvider
	if err := a.authService.GetDB().Where("id = ?", relayStateObj.SSOProviderID).First(&ssoProvider).Error; err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	ssoProviderObj, err := services.NewSSOProvider(&ssoProvider)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Get SAML configuration
	samlConfig, err := samlService.GetSAMLProvider(c.Request.Context(), ssoProviderObj)
	if err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	// Create certificate service
	certService := saml.NewCertService("./certs/saml.crt", "./certs/saml.key")

	// Create SAML provider instance
	samlProvider, err := samlService.CreateSAMLProvider(c.Request.Context(), samlConfig, certService)
	if err != nil {
		slog.Error("Failed to create SAML provider", "error", err)
		return consts.UNEXPECTED_FAILURE
	}

	// Process SAML Response (SAML doesn't use redirect_uri)
	oauthResp, err := samlProvider.ExchangeCodeForToken(c.Request.Context(), samlResponse, "")
	if err != nil {
		return consts.BAD_JWT
	}

	// Create or find user account
	ctx := context.WithValue(c.Request.Context(), httpRequestContextKey, c.Request)
	user, err := a.findOrCreateUserFromOAuth(ctx, &OAuthUserInfo{
		ID:       oauthResp.UserInfo.UID,
		Email:    oauthResp.UserInfo.Email,
		Name:     oauthResp.UserInfo.Name,
		Picture:  oauthResp.UserInfo.Avatar,
		Verified: true,
	}, "saml")
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Create session
	session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(), user, "aal1", []string{"saml"},
		c.GetHeader("User-Agent"), c.ClientIP(),
	)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Clean up relay state
	if err := samlService.DeleteRelayState(c.Request.Context(), relayState); err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Convert user to response format
	userResp := convertUserToResponse(a.authService, user.GetModel())

	// Calculate expires_in from expires_at
	expiresIn := int(expiresAt - time.Now().Unix())
	if expiresIn < 0 {
		expiresIn = 0
	}

	// Create session response
	sessionResp := &Session{
		ID:           session.HashID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
		User:         userResp,
	}

	// Validate redirect URL from relay state
	redirectTo := ""
	if relayStateObj.RedirectTo != nil && *relayStateObj.RedirectTo != "" {
		redirectService := a.createRedirectService()
		redirectTo = redirectService.ValidateAndGetRedirectTo(*relayStateObj.RedirectTo)
		slog.Info("SSO: Redirect URL validated", "original", *relayStateObj.RedirectTo, "validated", redirectTo)
	}

	resp := &AuthData{
		User:       userResp,
		Session:    sessionResp,
		RedirectTo: redirectTo,
	}

	return c.Render(resp)
}

// LinkIdentity links an external identity to existing user
// POST /user/identities/authorize
func (a *AuthController) LinkIdentity(c *pin.Context) error {
	req := &SignInWithOAuthRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate provider
	if req.Provider == "" {
		return consts.VALIDATION_FAILED
	}

	// Extract JWT from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return consts.NO_AUTHORIZATION
	}

	panic("not implemented")
}

// UnlinkIdentity removes an external identity from user
// DELETE /user/identities/{identity_id}
func (a *AuthController) UnlinkIdentity(c *pin.Context) error {
	identityID := c.Param("identity_id")
	if identityID == "" {
		return consts.VALIDATION_FAILED
	}

	// Extract JWT from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return consts.NO_AUTHORIZATION
	}

	// Extract token
	token := extractBearerToken(authHeader)
	if token == "" {
		return consts.BAD_JWT
	}

	// Validate JWT and extract user info
	claims, err := a.authService.ValidateJWT(token)
	if err != nil {
		return consts.BAD_JWT
	}

	// Extract user ID from claims
	userID, err := extractUserIDFromToken(claims)
	if err != nil {
		return consts.BAD_JWT
	}

	// Get user with identities
	user, err := a.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Verify the identity belongs to the user
	identityExists := false
	for _, identity := range user.Identities {
		if fmt.Sprintf("%d", identity.ID) == identityID {
			identityExists = true
			break
		}
	}

	if !identityExists {
		return consts.VALIDATION_FAILED
	}

	// Check if user has other authentication methods
	hasPassword := user.EncryptedPassword != nil && *user.EncryptedPassword != ""
	hasOtherIdentities := len(user.Identities) > 1

	if !hasPassword && !hasOtherIdentities {
		// User would have no way to log in after unlinking
		return consts.VALIDATION_FAILED
	}

	// Remove the identity from database
	if err := a.authService.GetDB().WithContext(c.Request.Context()).Where("id = ? AND instance_id = ?", identityID, a.authService.GetInstanceId()).Delete(&models.Identity{}).Error; err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Get updated user
	user, err = a.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Convert user to response format
	userResp := convertUserToResponse(a.authService, user.GetModel())

	resp := &UserResponse{
		User: userResp,
	}

	return c.Render(resp)
}
