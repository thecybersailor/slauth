package tests

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TokenErrorScenariosTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *TokenErrorScenariosTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// Scenario 1: Access Token Missing
func (suite *TokenErrorScenariosTestSuite) TestAccessTokenMissing() {
	suite.T().Log("=== Scenario 1: Access Token Missing ===")

	// Try to access protected endpoint without token
	response := suite.helper.MakeGETRequest(suite.T(), "/auth/user")

	suite.T().Logf("Status Code: %d", response.ResponseRecorder.Code)
	suite.T().Logf("Response Body: %s", response.ResponseRecorder.Body.String())

	suite.Equal(401, response.ResponseRecorder.Code, "Should return 401 when access token is missing")

	// Parse response body
	var responseBody map[string]any
	err := json.Unmarshal(response.ResponseRecorder.Body.Bytes(), &responseBody)
	suite.NoError(err, "Should be able to parse response body")

	suite.T().Logf("Parsed Response: %+v", responseBody)
}

// Scenario 2: Access Token Invalid (malformed)
func (suite *TokenErrorScenariosTestSuite) TestAccessTokenInvalid() {
	suite.T().Log("=== Scenario 2: Access Token Invalid (malformed) ===")

	// Try to access protected endpoint with invalid token
	invalidToken := "this-is-not-a-valid-jwt-token"
	response := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", invalidToken)

	suite.T().Logf("Status Code: %d", response.ResponseRecorder.Code)
	suite.T().Logf("Response Body: %s", response.ResponseRecorder.Body.String())

	suite.Equal(401, response.ResponseRecorder.Code, "Should return 401 when access token is invalid")

	// Parse response body
	var responseBody map[string]any
	err := json.Unmarshal(response.ResponseRecorder.Body.Bytes(), &responseBody)
	suite.NoError(err, "Should be able to parse response body")

	suite.T().Logf("Parsed Response: %+v", responseBody)
}

// Scenario 3: Access Token Expired
func (suite *TokenErrorScenariosTestSuite) TestAccessTokenExpired() {
	suite.T().Log("=== Scenario 3: Access Token Expired ===")

	// Create user and get valid session
	email := "token-expired@example.com"
	password := "TestPassword123!"

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

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)

	// Verify token works initially
	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access with valid token")

	// Now revoke the session to simulate expired token
	sessionId := session["id"].(string)
	revokeHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	revokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions/"+sessionId, nil, revokeHeaders)
	suite.Equal(200, revokeResponse.ResponseRecorder.Code, "Session revoke should succeed")

	// Try to use the token after session revoked (simulates expired scenario)
	expiredResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)

	suite.T().Logf("Status Code: %d", expiredResponse.ResponseRecorder.Code)
	suite.T().Logf("Response Body: %s", expiredResponse.ResponseRecorder.Body.String())

	suite.Equal(401, expiredResponse.ResponseRecorder.Code, "Should return 401 when session is revoked")

	// Parse response body
	var responseBody map[string]any
	err := json.Unmarshal(expiredResponse.ResponseRecorder.Body.Bytes(), &responseBody)
	suite.NoError(err, "Should be able to parse response body")

	suite.T().Logf("Parsed Response: %+v", responseBody)
}

// Scenario 4: Refresh Token Invalid
func (suite *TokenErrorScenariosTestSuite) TestRefreshTokenInvalid() {
	suite.T().Log("=== Scenario 4: Refresh Token Invalid ===")

	// Try to refresh with invalid refresh token
	refreshRequestBody := S{
		"grant_type":    "refresh_token",
		"refresh_token": "this-is-not-a-valid-refresh-token",
	}

	refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequestBody)

	suite.T().Logf("Status Code: %d", refreshResponse.ResponseRecorder.Code)
	suite.T().Logf("Response Body: %s", refreshResponse.ResponseRecorder.Body.String())

	// Refresh token errors return 401 with error in body
	suite.Equal(401, refreshResponse.ResponseRecorder.Code, "Refresh request returns 401")
	suite.helper.HasError(suite.T(), refreshResponse, "refresh_token_not_found", "Should fail with invalid refresh token")

	suite.T().Logf("Parsed Response: %+v", refreshResponse.Response.Error)
}

// Scenario 5: Refresh Token Expired (used after revoked)
func (suite *TokenErrorScenariosTestSuite) TestRefreshTokenExpired() {
	suite.T().Log("=== Scenario 5: Refresh Token Expired ===")

	// Create user and get session with refresh token
	email := "refresh-expired@example.com"
	password := "TestPassword123!"

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

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	refreshToken := session["refresh_token"].(string)
	accessToken := session["access_token"].(string)

	// Verify refresh token works initially
	refreshRequestBody := S{
		"refresh_token": refreshToken,
	}

	firstRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequestBody)
	suite.Equal(200, firstRefreshResponse.ResponseRecorder.Code, "First refresh should succeed")

	// Revoke the session
	sessionId := session["id"].(string)
	revokeHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	revokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions/"+sessionId, nil, revokeHeaders)
	suite.Equal(200, revokeResponse.ResponseRecorder.Code, "Session revoke should succeed")

	// Wait a moment to ensure revocation is processed
	time.Sleep(100 * time.Millisecond)

	// Try to use the refresh token after session revoked
	expiredRefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequestBody)

	suite.T().Logf("Status Code: %d", expiredRefreshResponse.ResponseRecorder.Code)
	suite.T().Logf("Response Body: %s", expiredRefreshResponse.ResponseRecorder.Body.String())

	// Refresh token errors return 401 with error in body
	// Note: RevokeUserSession explicitly revokes refresh tokens, so error is refresh_token_not_found
	suite.Equal(401, expiredRefreshResponse.ResponseRecorder.Code, "Refresh request returns 401")
	suite.helper.HasError(suite.T(), expiredRefreshResponse, "refresh_token_not_found", "Should fail with expired refresh token")

	suite.T().Logf("Parsed Response: %+v", expiredRefreshResponse.Response.Error)
}

func TestTokenErrorScenariosTestSuite(t *testing.T) {
	suite.Run(t, new(TokenErrorScenariosTestSuite))
}
