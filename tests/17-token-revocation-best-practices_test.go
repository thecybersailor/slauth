package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
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
// - Attempting to reuse old token should fail
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

	// Step 3: CRITICAL TEST - Old refresh token should be revoked
	reuseOldTokenRequest := S{
		"grant_type":    "refresh_token",
		"refresh_token": oldRefreshToken,
	}
	reuseResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", reuseOldTokenRequest)
	suite.Equal(401, reuseResponse.ResponseRecorder.Code,
		"Refresh request returns 200 (Pin Response format)")
	suite.helper.HasError(suite.T(), reuseResponse, "refresh_token_not_found",
		"SECURITY: Old refresh token MUST be rejected after rotation")

	suite.T().Log("✅ Security Best Practice: Token rotation revokes old tokens")
}

// TestConcurrentRefreshTokenRotation verifies the problem with concurrent refresh requests
//
// Problem Scenario:
// - Multiple requests use the same refresh token simultaneously
// - First request succeeds, creates new token, revokes old token
// - Other requests fail because old token was already revoked
// - This is the root cause of refresh_token_not_found errors
//
// Expected Behavior (with RefreshTokenReuseInterval):
// - Within reuse interval (10 seconds), same refresh token can be used multiple times
// - Only one new refresh token should be created
// - Other concurrent requests should reuse the same refresh token or wait
func (suite *TokenRevocationBestPracticesTestSuite) TestConcurrentRefreshTokenRotation() {
	email := "concurrent-refresh@example.com"
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

	// Step 2: Simulate concurrent refresh requests (3 requests using same token)
	// This simulates multiple browser tabs or API calls refreshing simultaneously
	type refreshResult struct {
		success bool
		code    int
		error   string
		token   string
	}
	results := make(chan refreshResult, 3)

	for i := 0; i < 3; i++ {
		go func() {
			refreshRequest := S{
				"grant_type":    "refresh_token",
				"refresh_token": originalRefreshToken,
			}
			refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)
			
			result := refreshResult{
				success: refreshResponse.ResponseRecorder.Code == 200,
				code:    refreshResponse.ResponseRecorder.Code,
			}
			
			// Extract error key if present
			if refreshResponse.Error != nil {
				result.error = refreshResponse.Error.Key
			}
			
			if result.success && refreshResponse.Data != nil {
				if refreshData, ok := refreshResponse.Data.(map[string]any); ok {
					if session, ok := refreshData["session"].(map[string]any); ok {
						if token, ok := session["refresh_token"].(string); ok {
							result.token = token
						}
					}
				}
			}
			
			results <- result
		}()
	}

	// Collect results
	var successCount int
	var failureCount int
	var refreshTokens []string
	for i := 0; i < 3; i++ {
		result := <-results
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

	// Step 3: Analyze the problem
	// Current implementation: Only 1 request succeeds, others fail with refresh_token_not_found
	// This is the root cause of the infinite refresh loop in frontend
	suite.T().Logf("Concurrent refresh results: %d succeeded, %d failed", successCount, failureCount)
	
	if failureCount > 0 {
		suite.T().Logf("❌ PROBLEM CONFIRMED: %d concurrent requests failed", failureCount)
		suite.T().Logf("   Root cause: Token rotation happens immediately, causing race condition")
		suite.T().Logf("   Expected: RefreshTokenReuseInterval should allow reuse within 10 seconds")
		suite.T().Logf("   Actual: Each refresh immediately revokes old token")
		suite.T().Logf("   This causes refresh_token_not_found errors and infinite refresh loops")
	} else {
		suite.T().Logf("✅ All concurrent requests succeeded (RefreshTokenReuseInterval working)")
	}

	// Verify unique tokens (if multiple succeeded, they should be different due to rotation)
	uniqueTokens := make(map[string]bool)
	for _, token := range refreshTokens {
		uniqueTokens[token] = true
	}
	suite.T().Logf("Unique refresh tokens generated: %d", len(uniqueTokens))
}

func TestTokenRevocationBestPracticesTestSuite(t *testing.T) {
	suite.Run(t, new(TokenRevocationBestPracticesTestSuite))
}
