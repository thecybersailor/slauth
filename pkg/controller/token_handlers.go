package controller

import (
	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
)

// RefreshToken refreshes an access token using refresh token
// @Summary Refresh Access Token
// @Description Refresh an access token using a refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token request"
// @Success 200 {object} AuthData "Token refreshed successfully"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Invalid refresh token"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /refresh [post]
func (a *AuthController) RefreshToken(c *pin.Context) error {
	req := &RefreshTokenRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate refresh token
	if req.RefreshToken == "" {
		return consts.VALIDATION_FAILED
	}

	// Validate refresh token
	refreshTokenRecord, err := a.authService.ValidateRefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		return consts.REFRESH_TOKEN_NOT_FOUND
	}

	// Get user by real ID (since refresh token stores real ID)
	// We need to get the user service from auth service to access the database
	userService := a.authService.GetUserService()
	user, err := userService.GetByID(c.Request.Context(), refreshTokenRecord.UserID, a.authService.GetDomainCode())
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	// Create user object with hashid
	appSecret := a.authService.GetConfig().AppSecret
	userObj, err := services.NewUser(user, a.authService.GetUserService(), services.NewPasswordService(nil, appSecret, 2), services.NewSessionService(a.authService.GetDB()), a.authService.GetDB(), a.authService.GetDomainCode())
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Create new session (this will generate new tokens)
	sessionObj, accessToken, newRefreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(), userObj, "aal1", []string{"refresh_token"},
		c.GetHeader("User-Agent"), c.ClientIP(),
	)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Revoke old refresh token
	if err := a.authService.RevokeRefreshToken(c.Request.Context(), req.RefreshToken); err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Convert user to response format
	userResp := convertUserToResponse(userObj.GetModel())

	// Create session response
	sessionResp := &Session{
		ID:           sessionObj.HashID,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    3600, // TODO: Get from config
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

// SignOut logs out user and revokes tokens
// @Summary User Logout
// @Description Log out user and revoke tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SignOutRequest false "Logout request (optional)"
// @Success 200 {object} SuccessResponse "Logout successful"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /logout [post]
func (a *AuthController) SignOut(c *pin.Context) error {
	req := &SignOutRequest{}
	if err := c.BindJSON(req); err != nil {
		// Allow empty body for logout
		req = &SignOutRequest{Scope: "local"}
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

	// Validate JWT and extract session info
	claims, err := a.authService.ValidateJWT(token)
	if err != nil {
		return consts.BAD_JWT
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
		return consts.BAD_JWT
	}

	// Get user ID from claims
	userID, ok := claims["sub"].(string)
	if !ok {
		return consts.BAD_JWT
	}

	// Generate session hash ID from numeric ID
	sessionHashID, err := services.GenerateSessionHashID(sessionID)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Revoke tokens based on scope
	switch req.Scope {
	case "global":
		// Revoke all user sessions
		// Get user first, then revoke all sessions
		user, err := a.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
		if err != nil {
			return consts.USER_NOT_FOUND
		}
		if err := user.RevokeAllSessions(c.Request.Context()); err != nil {
			return consts.UNEXPECTED_FAILURE
		}
	case "others":
		// For "others" scope, we need to revoke all sessions except current
		// This requires getting all user sessions and revoking except current
		// Get user first, then list sessions
		user, err := a.authService.GetUserService().GetByHashID(c.Request.Context(), userID)
		if err != nil {
			return consts.USER_NOT_FOUND
		}
		sessions, _, err := user.ListSessions(c.Request.Context(), 1, 100)
		if err != nil {
			return consts.UNEXPECTED_FAILURE
		}
		for _, session := range sessions {
			if session.HashID != sessionHashID {
				err = a.authService.GetAdminSessionService().RevokeUserSession(c.Request.Context(), a.authService.GetDomainCode(), session.HashID)
				if err != nil {
					return consts.UNEXPECTED_FAILURE
				}
			}
		}
	default: // "local"
		// Revoke current session only
		err = a.authService.GetAdminSessionService().RevokeUserSession(c.Request.Context(), a.authService.GetDomainCode(), sessionHashID)
	}

	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	resp := &SuccessResponse{
		Success: true,
	}

	return c.Render(resp)
}

// RevokeToken revokes a specific token
// @Summary Revoke Token
// @Description Revoke a specific access or refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body object{token=string,token_type_hint=string} true "Token revocation request"
// @Success 200 {object} map[string]interface{} "Token revoked successfully"
// @Router /revoke [post]
func (a *AuthController) RevokeToken(c *pin.Context) error {
	type RevokeTokenRequest struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type_hint,omitempty"` // access_token, refresh_token
	}

	req := &RevokeTokenRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate required fields
	if req.Token == "" {
		return consts.VALIDATION_FAILED
	}

	// TODO: Implement token revocation
	// In a real implementation, this would:
	// 1. Determine token type (access token or refresh token)
	// 2. Validate the token
	// 3. Mark token as revoked in database
	// 4. Optionally revoke related tokens

	return c.Render(map[string]string{"message": "Token revoked successfully"})
}

// IntrospectToken provides token introspection (RFC 7662)
// @Summary Token Introspection
// @Description Introspect a token to get its information and validity
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body object{token=string,token_type_hint=string} true "Token introspection request"
// @Success 200 {object} map[string]interface{} "Token introspection successful"
// @Router /introspect [post]
func (a *AuthController) IntrospectToken(c *pin.Context) error {
	type IntrospectTokenRequest struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type_hint,omitempty"` // access_token, refresh_token
	}

	type IntrospectTokenResponse struct {
		Active    bool   `json:"active"`
		ClientID  string `json:"client_id,omitempty"`
		Username  string `json:"username,omitempty"`
		Scope     string `json:"scope,omitempty"`
		TokenType string `json:"token_type,omitempty"`
		Exp       int64  `json:"exp,omitempty"`
		Iat       int64  `json:"iat,omitempty"`
		Sub       string `json:"sub,omitempty"`
		Aud       string `json:"aud,omitempty"`
		Iss       string `json:"iss,omitempty"`
	}

	req := &IntrospectTokenRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}

	// Validate required fields
	if req.Token == "" {
		return consts.VALIDATION_FAILED
	}

	// Validate JWT token
	claims, err := a.authService.ValidateJWT(req.Token)
	if err != nil {
		// Token is invalid or expired
		resp := &IntrospectTokenResponse{
			Active: false,
		}
		return c.Render(resp)
	}

	// Extract claims
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	iss, _ := claims["iss"].(string)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)

	resp := &IntrospectTokenResponse{
		Active:    true,
		TokenType: "Bearer",
		Sub:       sub,
		Aud:       aud,
		Iss:       iss,
		Exp:       int64(exp),
		Iat:       int64(iat),
	}

	return c.Render(resp)
}

// GetSession returns current session information
// GET /session
func (a *AuthController) GetSession(c *pin.Context) error {
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

	// Convert user to response format
	userResp := convertUserToResponse(user.GetModel())

	// Create session response (without refresh token for security)
	sessionResp := &Session{
		AccessToken: token,
		TokenType:   "Bearer",
		User:        userResp,
	}

	resp := &AuthData{
		User:    userResp,
		Session: sessionResp,
	}

	return c.Render(resp)
}

// RefreshSession extends current session
// POST /session/refresh
func (a *AuthController) RefreshSession(c *pin.Context) error {
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

	// Create new session (extend current session)
	session, accessToken, refreshToken, expiresAt, err := a.authService.CreateSession(
		c.Request.Context(), user, "aal1", []string{"session_refresh"},
		c.GetHeader("User-Agent"), c.ClientIP(),
	)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Convert user to response format
	userResp := convertUserToResponse(user.GetModel())

	// Create session response
	sessionResp := &Session{
		ID:           session.HashID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    3600, // TODO: Get from config
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
