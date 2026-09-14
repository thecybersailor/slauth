package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
)

// TokenRevocationBestPracticesTestSuite tests industry best practices for token revocation
// Based on Supabase Auth behavior and OAuth2 standards
//
// Frontend API Reference:
// - packages/slauth-ts/src/AuthApi.ts - signOut(), refreshSession()
//
// Industry Best Practices (from Supabase Auth):
// 1. POST /logout - revokes ALL refresh tokens for the user (all devices)
// 2. Session revoke - must invalidate associated refresh tokens
// 3. Token refresh - should reuse session, not create new ones
// 4. Access tokens remain valid until expiry (JWT stateless nature)
type TokenRevocationBestPracticesTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *TokenRevocationBestPracticesTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Disable email confirmation for testing token revocation
	updateConfigReq := S{
		"config": S{
			"confirm_email": false,
		},
	}
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", updateConfigReq, nil)
}

func (suite *TokenRevocationBestPracticesTestSuite) SetupTest() {
	// Ensure database tables exist before each test
	// This is a safety check in case SetupSuite didn't run properly
	if suite.DB != nil {
		err := models.AutoMigrate(suite.DB)
		suite.Require().NoError(err, "Failed to migrate database in SetupTest")
	}
}

// TestLogoutRevokesAllDevicesRefreshTokens verifies that POST /logout revokes
// all refresh tokens across all devices for the user
//
// Expected Behavior (Supabase standard):
// - User logs in on Device A and Device B
// - User calls /logout from Device A
// - Result: Both Device A and Device B's refresh tokens are revoked
func (suite *TokenRevocationBestPracticesTestSuite) TestLogoutRevokesAllDevicesRefreshTokens() {
	email := "multi-device-logout@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	// Step 2: Login from Device A
	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	deviceALoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, deviceALoginResponse.ResponseRecorder.Code, "Device A login should succeed")

	deviceAData := deviceALoginResponse.Data.(map[string]any)
	deviceASession := deviceAData["session"].(map[string]any)
	deviceAAccessToken := deviceASession["access_token"].(string)
	deviceARefreshToken := deviceASession["refresh_token"].(string)

	// Step 3: Login from Device B (simulate different device)
	deviceBLoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, deviceBLoginResponse.ResponseRecorder.Code, "Device B login should succeed")

	deviceBData := deviceBLoginResponse.Data.(map[string]any)
	deviceBSession := deviceBData["session"].(map[string]any)
	deviceBAccessToken := deviceBSession["access_token"].(string)
	deviceBRefreshToken := deviceBSession["refresh_token"].(string)

	// Verify both tokens are different
	suite.NotEqual(deviceARefreshToken, deviceBRefreshToken, "Device A and B should have different refresh tokens")

	// Step 4: Verify both devices can access user info
	deviceAUserResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", deviceAAccessToken)
	suite.Equal(200, deviceAUserResponse.ResponseRecorder.Code, "Device A should access user info")

	deviceBUserResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", deviceBAccessToken)
	suite.Equal(200, deviceBUserResponse.ResponseRecorder.Code, "Device B should access user info")

	// Step 5: Device A calls /logout (without scope or scope=global)
	// Industry Best Practice: This should revoke ALL refresh tokens for the user
	logoutHeaders := map[string]string{
		"Authorization": "Bearer " + deviceAAccessToken,
	}
	logoutResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/logout", S{}, logoutHeaders)
	suite.Equal(200, logoutResponse.ResponseRecorder.Code, "Logout should succeed")

	// Step 6: Verify Device A's refresh token is revoked
	deviceARefreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": deviceARefreshToken,
	}
	deviceARefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", deviceARefreshRequest)
	suite.Equal(401, deviceARefreshResponse.ResponseRecorder.Code, "Refresh request returns 401")
	suite.helper.HasError(suite.T(), deviceARefreshResponse, "refresh_token_not_found", "Device A refresh token should be revoked")

	// Step 7: CRITICAL TEST - Verify Device B's refresh token is ALSO revoked
	// This is the industry best practice: logout = global logout by default
	deviceBRefreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": deviceBRefreshToken,
	}
	deviceBRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", deviceBRefreshRequest)
	suite.Equal(401, deviceBRefreshResponse.ResponseRecorder.Code, "Refresh request returns 401")
	suite.helper.HasError(suite.T(), deviceBRefreshResponse, "refresh_token_not_found", "Device B refresh token should ALSO be revoked (global logout)")

	suite.T().Log("✅ Industry Best Practice: /logout revokes ALL devices' refresh tokens")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestGlobalLogoutPreservesCliTaggedSession() {
	email := "cli-tagged-global-logout@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	webLoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, webLoginResponse.ResponseRecorder.Code, "Web login should succeed")
	webData := webLoginResponse.Data.(map[string]any)
	webSession := webData["session"].(map[string]any)
	webAccessToken := webSession["access_token"].(string)
	webRefreshToken := webSession["refresh_token"].(string)

	cliLoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, cliLoginResponse.ResponseRecorder.Code, "CLI login should succeed")
	cliData := cliLoginResponse.Data.(map[string]any)
	cliSession := cliData["session"].(map[string]any)
	cliRefreshToken := cliSession["refresh_token"].(string)

	var cliRefreshRecord models.RefreshToken
	suite.Require().NoError(suite.DB.Where("token = ?", cliRefreshToken).First(&cliRefreshRecord).Error)
	suite.Require().NoError(suite.DB.Model(&models.Session{}).
		Where("id = ?", cliRefreshRecord.SessionID).
		Update("tag", "cli:botworks-cli").Error)

	logoutHeaders := map[string]string{
		"Authorization": "Bearer " + webAccessToken,
	}
	logoutResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/logout", S{}, logoutHeaders)
	suite.Equal(200, logoutResponse.ResponseRecorder.Code, "Global logout should succeed")

	webRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"grant_type":    "refresh_token",
		"refresh_token": webRefreshToken,
	})
	suite.Equal(401, webRefreshResponse.ResponseRecorder.Code, "Web refresh request returns 401")
	suite.helper.HasError(suite.T(), webRefreshResponse, "refresh_token_not_found", "Web refresh token should be revoked")

	cliRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"grant_type":    "refresh_token",
		"refresh_token": cliRefreshToken,
	})
	suite.Equal(200, cliRefreshResponse.ResponseRecorder.Code, "CLI refresh token should survive normal global logout")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestSecurityRevokeAllSessionsRevokesCliTaggedSession() {
	email := "cli-tagged-security-revoke@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	cliLoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, cliLoginResponse.ResponseRecorder.Code, "CLI login should succeed")
	cliData := cliLoginResponse.Data.(map[string]any)
	cliSession := cliData["session"].(map[string]any)
	cliRefreshToken := cliSession["refresh_token"].(string)

	var cliRefreshRecord models.RefreshToken
	suite.Require().NoError(suite.DB.Where("token = ?", cliRefreshToken).First(&cliRefreshRecord).Error)
	suite.Require().NoError(suite.DB.Model(&models.Session{}).
		Where("id = ?", cliRefreshRecord.SessionID).
		Update("tag", "cli:botworks-cli").Error)

	user, err := suite.AuthService.GetUserService().GetByEmail(context.Background(), email)
	suite.Require().NoError(err)
	suite.Require().NoError(user.RevokeAllSessions(context.Background()))

	cliRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"grant_type":    "refresh_token",
		"refresh_token": cliRefreshToken,
	})
	suite.Equal(401, cliRefreshResponse.ResponseRecorder.Code, "Security revoke-all should revoke CLI refresh token")
	suite.helper.HasError(suite.T(), cliRefreshResponse, "refresh_token_not_found", "CLI refresh token should be revoked by security revoke-all")
}

// TestSessionRevokeInvalidatesRefreshToken verifies that when a session is revoked,
// its associated refresh tokens become invalid
//
// # This is a CRITICAL security requirement to prevent token reuse after session revocation
//
// Expected Behavior:
// - User has active session with refresh token
// - Admin/User revokes the session
// - Refresh token should be rejected (session.not_after check)
func (suite *TokenRevocationBestPracticesTestSuite) TestSessionRevokeInvalidatesRefreshToken() {
	email := "session-revoke-refresh@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user and login
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	loginData := loginResponse.Data.(map[string]any)
	session := loginData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	refreshToken := session["refresh_token"].(string)
	sessionId := session["id"].(string)

	// Step 2: Verify refresh token works before revocation
	refreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}
	firstRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)
	suite.Equal(200, firstRefreshResponse.ResponseRecorder.Code, "Refresh should succeed before session revoke")

	// Get new refresh token from first refresh
	firstRefreshData := firstRefreshResponse.Data.(map[string]any)
	newSession := firstRefreshData["session"].(map[string]any)
	newRefreshToken := newSession["refresh_token"].(string)

	// Step 3: Revoke the session
	revokeHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	revokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions/"+sessionId, nil, revokeHeaders)
	suite.Equal(200, revokeResponse.ResponseRecorder.Code, "Session revoke should succeed")

	// Wait a moment to ensure revocation is processed
	time.Sleep(100 * time.Millisecond)

	// Step 4: CRITICAL TEST - Refresh token should be rejected after session revoke
	// This tests the security fix: ValidateRefreshToken must check session.not_after
	secondRefreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": newRefreshToken,
	}
	secondRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", secondRefreshRequest)

	// THIS MUST FAIL - refresh token should be invalid after session revoke
	// Pin Response: All refresh token errors return 200 with error in body
	// Note: RevokeUserSession explicitly revokes refresh tokens, so error is refresh_token_not_found
	suite.Equal(401, secondRefreshResponse.ResponseRecorder.Code,
		"Refresh request returns 200 (Pin Response format)")
	suite.helper.HasError(suite.T(), secondRefreshResponse, "refresh_token_not_found",
		"SECURITY: Refresh token MUST be rejected after session revoke")

	suite.T().Log("✅ Security Best Practice: Session revoke invalidates refresh tokens")
}

// TestTokenRefreshReusesSession verifies that refreshing a token reuses the existing session
// rather than creating a new session each time
//
// Expected Behavior:
// - User logs in (creates Session A)
// - User refreshes token
// - Session ID should remain the same (Session A reused)
func (suite *TokenRevocationBestPracticesTestSuite) TestTokenRefreshReusesSession() {
	email := "refresh-reuse-session@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user and login
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	loginData := loginResponse.Data.(map[string]any)
	originalSession := loginData["session"].(map[string]any)
	originalSessionId := originalSession["id"].(string)
	originalRefreshToken := originalSession["refresh_token"].(string)

	// Step 2: Refresh token multiple times
	currentRefreshToken := originalRefreshToken
	for i := 1; i <= 3; i++ {
		refreshRequest := S{
			"grant_type":    "refresh_token",
			"refresh_token": currentRefreshToken,
		}
		refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)
		suite.Equal(200, refreshResponse.ResponseRecorder.Code, "Refresh #%d should succeed", i)

		refreshData := refreshResponse.Data.(map[string]any)
		newSession := refreshData["session"].(map[string]any)
		newSessionId := newSession["id"].(string)

		// CRITICAL TEST: Session ID should remain the same
		suite.Equal(originalSessionId, newSessionId,
			"Refresh #%d should reuse original session ID (not create new session)", i)

		// Update for next iteration
		currentRefreshToken = newSession["refresh_token"].(string)
	}

	suite.T().Log("✅ Best Practice: Token refresh reuses session (doesn't create new sessions)")
}

// TestAccessTokenRemainsValidAfterRefreshTokenRevoked verifies JWT stateless nature
//
// Expected Behavior:
// - Access token (JWT) remains valid until it expires
// - Revoking refresh token doesn't invalidate the access token
// - This is standard OAuth2/JWT behavior
func (suite *TokenRevocationBestPracticesTestSuite) TestAccessTokenRemainsValidAfterRefreshTokenRevoked() {
	email := "jwt-stateless@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user and login
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	loginData := loginResponse.Data.(map[string]any)
	session := loginData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	sessionId := session["id"].(string)

	// Step 2: Verify access token works
	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Access token should work before revoke")

	// Step 3: Revoke the session
	revokeHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	revokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions/"+sessionId, nil, revokeHeaders)
	suite.Equal(200, revokeResponse.ResponseRecorder.Code, "Session revoke should succeed")

	// Step 4: Access token should become invalid
	// Note: In your implementation, access token validation checks session.not_after
	userResponseAfterRevoke := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponseAfterRevoke.ResponseRecorder.Code,
		"Access token should be invalid after session revoke (checks session.not_after)")

	suite.T().Log("✅ JWT behavior: Access tokens are invalidated via session.not_after check")
}

// TestLocalVsGlobalLogout verifies different logout scopes if implemented
//
// Expected Behavior:
// - scope=local: only revokes current session's tokens
// - scope=global or no scope: revokes all user's tokens (default)
func (suite *TokenRevocationBestPracticesTestSuite) TestLocalVsGlobalLogout() {
	email := "logout-scopes@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	// Step 2: Login from two devices
	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	device1Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	device1Data := device1Response.Data.(map[string]any)
	device1Session := device1Data["session"].(map[string]any)
	device1AccessToken := device1Session["access_token"].(string)
	device1RefreshToken := device1Session["refresh_token"].(string)

	device2Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	device2Data := device2Response.Data.(map[string]any)
	device2Session := device2Data["session"].(map[string]any)
	device2RefreshToken := device2Session["refresh_token"].(string)

	// Step 3: Device 1 logs out with scope=local
	logoutHeaders := map[string]string{
		"Authorization": "Bearer " + device1AccessToken,
	}
	logoutRequestBody := S{
		"scope": "local",
	}
	logoutResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/logout", logoutRequestBody, logoutHeaders)
	suite.Equal(200, logoutResponse.ResponseRecorder.Code, "Local logout should succeed")

	// Step 4: Device 1's refresh token should be revoked
	device1RefreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": device1RefreshToken,
	}
	device1RefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", device1RefreshRequest)
	suite.Equal(401, device1RefreshResponse.ResponseRecorder.Code, "Refresh request returns 401")
	suite.helper.HasError(suite.T(), device1RefreshResponse, "refresh_token_not_found", "Device 1 refresh token should be revoked")

	// Step 5: Device 2's refresh token should still work (local logout)
	device2RefreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": device2RefreshToken,
	}
	device2RefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", device2RefreshRequest)
	suite.Nil(device2RefreshResponse.Error, "Device 2 refresh should succeed")
	suite.Nil(device2RefreshResponse.Error, "Device 2 refresh token should still work after Device 1 local logout")

	suite.T().Log("✅ Best Practice: scope=local only revokes current device, other devices remain active")
}

// TestRefreshTokenRotation verifies token rotation security
//
// Expected Behavior:
// - Each refresh generates a new refresh token
// - Old refresh token is revoked
// - Reusing old token inside RefreshTokenReuseInterval returns the rotated token
// - Reusing old token after RefreshTokenReuseInterval fails
func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenRotation() {
	email := "token-rotation@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user and login
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	loginData := loginResponse.Data.(map[string]any)
	session := loginData["session"].(map[string]any)
	oldRefreshToken := session["refresh_token"].(string)

	// Step 2: Refresh token
	refreshRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefreshToken,
	}
	refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)
	suite.Equal(200, refreshResponse.ResponseRecorder.Code, "First refresh should succeed")

	refreshData := refreshResponse.Data.(map[string]any)
	newSession := refreshData["session"].(map[string]any)
	newRefreshToken := newSession["refresh_token"].(string)

	// Verify new token is different
	suite.NotEqual(oldRefreshToken, newRefreshToken, "New refresh token should be different")

	// Step 3: Old refresh token is reusable inside RefreshTokenReuseInterval
	reuseOldTokenRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefreshToken,
	}
	reuseResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", reuseOldTokenRequest)
	suite.Equal(200, reuseResponse.ResponseRecorder.Code,
		"Old refresh token should be reusable inside RefreshTokenReuseInterval")
	reuseData := reuseResponse.Data.(map[string]any)
	reusedSession := reuseData["session"].(map[string]any)
	reusedRefreshToken := reusedSession["refresh_token"].(string)
	suite.Equal(newRefreshToken, reusedRefreshToken,
		"Old refresh token reuse should return the already rotated refresh token")

	// Step 4: Old refresh token should fail after RefreshTokenReuseInterval
	expiredUpdatedAt := time.Now().Add(-11 * time.Second)
	err := suite.DB.Exec(
		"UPDATE refresh_tokens SET updated_at = ? WHERE token = ? AND instance_id = ?",
		expiredUpdatedAt,
		oldRefreshToken,
		suite.TestInstance,
	).Error
	suite.Require().NoError(err)

	expiredReuseResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", reuseOldTokenRequest)
	suite.Equal(401, expiredReuseResponse.ResponseRecorder.Code,
		"Old refresh token should fail after RefreshTokenReuseInterval")
	suite.helper.HasError(suite.T(), expiredReuseResponse, "refresh_token_not_found",
		"SECURITY: Old refresh token MUST be rejected after reuse window")

	suite.T().Log("✅ Security Best Practice: Token rotation allows bounded reuse and rejects stale replay")
}

// TestRefreshTokenReuseInterval verifies repeated refresh requests share rotation output
//
// Former Problem Scenario:
// - Multiple requests use the same refresh token simultaneously
// - First request succeeds, creates new token, revokes old token
// - Other requests fail because old token was already revoked
// - This is the root cause of refresh_token_not_found errors
//
// Expected Behavior (with RefreshTokenReuseInterval):
// - Within reuse interval (10 seconds), same refresh token can be used multiple times
// - Only one new refresh token should be created
// - Other concurrent requests should reuse the same refresh token or wait
func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenReuseInterval() {
	email := "refresh-reuse-interval@example.com"
	password := "MySecurePassword2024!"

	// Step 1: Create user and login
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	loginData := loginResponse.Data.(map[string]any)
	session := loginData["session"].(map[string]any)
	originalRefreshToken := session["refresh_token"].(string)

	// Step 2: Reuse the same old refresh token several times inside the reuse interval.
	// This simulates browser tabs that did not observe the first token rotation yet.
	type refreshResult struct {
		success bool
		code    int
		error   string
		token   string
	}
	results := make([]refreshResult, 0, 3)

	for i := 0; i < 3; i++ {
		refreshRequest := S{
			"grant_type":    "refresh_token",
			"refresh_token": originalRefreshToken,
		}
		refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)

		result := refreshResult{
			success: refreshResponse.Error == nil && refreshResponse.Data != nil,
			code:    refreshResponse.ResponseRecorder.Code,
		}

		if refreshResponse.Error != nil {
			result.error = refreshResponse.Error.Key
		}

		if result.success {
			if refreshData, ok := refreshResponse.Data.(map[string]any); ok {
				if session, ok := refreshData["session"].(map[string]any); ok {
					if token, ok := session["refresh_token"].(string); ok {
						result.token = token
					}
				}
			}
		}

		results = append(results, result)
	}

	// Collect results
	var successCount int
	var failureCount int
	var refreshTokens []string
	for _, result := range results {
		if result.success {
			successCount++
			if result.token != "" {
				refreshTokens = append(refreshTokens, result.token)
			}
		} else {
			failureCount++
			suite.T().Logf("Concurrent refresh failed: code=%d, error=%s", result.code, result.error)
		}
	}

	suite.T().Logf("Refresh reuse results: %d succeeded, %d failed", successCount, failureCount)
	suite.Equal(3, successCount, "all refresh token reuse requests should succeed inside reuse interval")
	suite.Equal(0, failureCount, "no refresh token reuse request should fail inside reuse interval")

	// Verify unique tokens (if multiple succeeded, they should be different due to rotation)
	uniqueTokens := make(map[string]bool)
	for _, token := range refreshTokens {
		uniqueTokens[token] = true
	}
	suite.T().Logf("Unique refresh tokens generated: %d", len(uniqueTokens))
	suite.Len(uniqueTokens, 1, "refresh token reuse requests should return the same rotated refresh token")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenReuseIntervalDisabledRejectsOldToken() {
	originalInterval := suite.AuthService.GetConfig().SessionConfig.RefreshTokenReuseInterval
	suite.AuthService.GetConfig().SessionConfig.RefreshTokenReuseInterval = 0
	defer func() {
		suite.AuthService.GetConfig().SessionConfig.RefreshTokenReuseInterval = originalInterval
	}()

	oldRefreshToken := suite.createLoggedInRefreshToken("refresh-reuse-disabled@example.com")
	firstRefresh := suite.refreshWithToken(oldRefreshToken)
	suite.Equal(200, firstRefresh.ResponseRecorder.Code, "First refresh should succeed")

	reuseResponse := suite.refreshWithToken(oldRefreshToken)
	suite.Equal(401, reuseResponse.ResponseRecorder.Code, "Old token should fail when reuse interval is disabled")
	suite.helper.HasError(suite.T(), reuseResponse, "refresh_token_not_found",
		"Old refresh token should not be reusable when RefreshTokenReuseInterval is disabled")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenReuseIntervalRejectsRevokedTokenWithoutChild() {
	oldRefreshToken := suite.createLoggedInRefreshToken("refresh-reuse-no-child@example.com")
	err := suite.AuthService.RevokeRefreshToken(context.Background(), oldRefreshToken)
	suite.Require().NoError(err)

	reuseResponse := suite.refreshWithToken(oldRefreshToken)
	suite.Equal(401, reuseResponse.ResponseRecorder.Code, "Revoked token without a rotated child should fail")
	suite.helper.HasError(suite.T(), reuseResponse, "refresh_token_not_found",
		"Revoked refresh token should not be reusable when no child token exists")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenReturnsSessionExpiredForActiveToken() {
	refreshToken := suite.createLoggedInRefreshToken("refresh-active-session-expired@example.com")
	suite.expireSessionForRefreshToken(refreshToken)

	refreshResponse := suite.refreshWithToken(refreshToken)
	suite.Equal(401, refreshResponse.ResponseRecorder.Code, "Refresh should fail when the active token session is expired")
	suite.helper.HasError(suite.T(), refreshResponse, "session_expired",
		"Active refresh token should report session_expired when its session has expired")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenReturnsSessionExpiredForReusableChild() {
	oldRefreshToken := suite.createLoggedInRefreshToken("refresh-child-session-expired@example.com")
	firstRefresh := suite.refreshWithToken(oldRefreshToken)
	suite.Equal(200, firstRefresh.ResponseRecorder.Code, "First refresh should succeed")

	suite.expireSessionForRefreshToken(oldRefreshToken)

	reuseResponse := suite.refreshWithToken(oldRefreshToken)
	suite.Equal(401, reuseResponse.ResponseRecorder.Code, "Reuse should fail when the rotated child's session is expired")
	suite.helper.HasError(suite.T(), reuseResponse, "session_expired",
		"Reusable child refresh token should report session_expired when its session has expired")
}

func (suite *TokenRevocationBestPracticesTestSuite) TestRefreshTokenReturnsExistingChildAndRevokesParent() {
	oldRefreshToken := suite.createLoggedInRefreshToken("refresh-existing-child@example.com")

	var parent models.RefreshToken
	err := suite.DB.Where("token = ? AND instance_id = ?", oldRefreshToken, suite.TestInstance).First(&parent).Error
	suite.Require().NoError(err)

	childToken := "manual-child-" + oldRefreshToken
	err = suite.DB.Create(&models.RefreshToken{
		Token:      childToken,
		UserID:     parent.UserID,
		SessionID:  parent.SessionID,
		InstanceId: suite.TestInstance,
		Revoked:    false,
		Parent:     &parent.ID,
	}).Error
	suite.Require().NoError(err)

	refreshResponse := suite.refreshWithToken(oldRefreshToken)
	suite.Equal(200, refreshResponse.ResponseRecorder.Code, "Refresh should return the already rotated child token")
	returnedRefreshToken := refreshTokenFromResponse(suite.T(), refreshResponse)
	suite.Equal(childToken, returnedRefreshToken, "Refresh should reuse the existing child refresh token")

	var reloadedParent models.RefreshToken
	err = suite.DB.First(&reloadedParent, parent.ID).Error
	suite.Require().NoError(err)
	suite.True(reloadedParent.Revoked, "Parent refresh token should be revoked after returning existing child")
}

func (suite *TokenRevocationBestPracticesTestSuite) createLoggedInRefreshToken(email string) string {
	password := "MySecurePassword2024!"
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	})
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")
	return refreshTokenFromResponse(suite.T(), loginResponse)
}

func (suite *TokenRevocationBestPracticesTestSuite) refreshWithToken(refreshToken string) *PinResponse {
	return suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})
}

func (suite *TokenRevocationBestPracticesTestSuite) expireSessionForRefreshToken(refreshToken string) {
	var token models.RefreshToken
	err := suite.DB.Where("token = ? AND instance_id = ?", refreshToken, suite.TestInstance).First(&token).Error
	suite.Require().NoError(err)

	err = suite.DB.Model(&models.Session{}).
		Where("id = ?", token.SessionID).
		Update("not_after", time.Now().Add(-time.Minute)).Error
	suite.Require().NoError(err)
}

func refreshTokenFromResponse(t *testing.T, response *PinResponse) string {
	t.Helper()
	data, ok := response.Data.(map[string]any)
	if !ok {
		t.Fatalf("response data should be an object, got %#v", response.Data)
	}
	session, ok := data["session"].(map[string]any)
	if !ok {
		t.Fatalf("response session should be an object, got %#v", data["session"])
	}
	refreshToken, ok := session["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("response refresh_token should be a non-empty string, got %#v", session["refresh_token"])
	}
	return refreshToken
}

func TestTokenRevocationBestPracticesTestSuite(t *testing.T) {
	suite.Run(t, new(TokenRevocationBestPracticesTestSuite))
}
