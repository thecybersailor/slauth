package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type SessionManagementTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SessionManagementTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

func (suite *SessionManagementTestSuite) TestRefreshToken() {
	email := "refresh-token@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Password login should succeed")
	suite.Nil(loginResponse.Response.Error, "Password login should not have error")

	suite.NotNil(loginResponse.Response.Data, "Login response should have data")
	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	refreshToken := session["refresh_token"].(string)
	suite.NotEmpty(refreshToken, "Refresh token should not be empty")

	refreshRequestBody := S{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequestBody)
	suite.Equal(200, refreshResponse.ResponseRecorder.Code, "Token refresh should succeed")
	suite.Nil(refreshResponse.Response.Error, "Token refresh should not have error")

	suite.NotNil(refreshResponse.Response.Data, "Refresh response should have data")
	refreshData := refreshResponse.Response.Data.(map[string]any)
	newSession := refreshData["session"].(map[string]any)

	suite.Contains(newSession, "access_token", "New session should have access_token")
	suite.Contains(newSession, "refresh_token", "New session should have refresh_token")
	suite.Contains(newSession, "expires_at", "New session should have expires_at")
	suite.Contains(newSession, "user", "New session should have user")

	newAccessToken := newSession["access_token"].(string)
	originalAccessToken := session["access_token"].(string)
	suite.NotEqual(newAccessToken, originalAccessToken, "New access token should be different from original")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", newAccessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access user info with new token")
	suite.Nil(userResponse.Response.Error, "Should not have error accessing user info")
}

func (suite *SessionManagementTestSuite) TestLogout() {
	email := "logout-test@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Password login should succeed")
	suite.Nil(loginResponse.Response.Error, "Password login should not have error")

	suite.NotNil(loginResponse.Response.Data, "Login response should have data")
	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	suite.NotEmpty(accessToken, "Access token should not be empty")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access user info before logout")
	suite.Nil(userResponse.Response.Error, "Should not have error accessing user info before logout")

	logoutRequestBody := S{
		"scope": "local",
	}

	logoutHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	logoutResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/logout", logoutRequestBody, logoutHeaders)
	suite.Equal(200, logoutResponse.ResponseRecorder.Code, "Logout should succeed")
	suite.Nil(logoutResponse.Response.Error, "Logout should not have error")

	userResponseAfterLogout := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponseAfterLogout.ResponseRecorder.Code, "Should return 401 after logout")
	suite.NotNil(userResponseAfterLogout.Response.Error, "Should have error after logout")
}

func (suite *SessionManagementTestSuite) TestRevokeSession() {
	email := "revoke-session@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Password login should succeed")
	suite.Nil(loginResponse.Response.Error, "Password login should not have error")

	suite.NotNil(loginResponse.Response.Data, "Login response should have data")
	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	sessionId := session["id"].(string)
	suite.NotEmpty(accessToken, "Access token should not be empty")
	suite.NotEmpty(sessionId, "Session ID should not be empty")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access user info before revoke")
	suite.Nil(userResponse.Response.Error, "Should not have error accessing user info before revoke")

	revokeHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	revokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions/"+sessionId, nil, revokeHeaders)
	suite.Equal(200, revokeResponse.ResponseRecorder.Code, "Session revoke should succeed")
	suite.Nil(revokeResponse.Response.Error, "Session revoke should not have error")

	userResponseAfterRevoke := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponseAfterRevoke.ResponseRecorder.Code, "Should return 401 after session revoke")
	suite.NotNil(userResponseAfterRevoke.Response.Error, "Should have error after session revoke")
}

func (suite *SessionManagementTestSuite) TestRevokeAllSessions() {
	email := "revoke-all-sessions@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Password login should succeed")
	suite.Nil(loginResponse.Response.Error, "Password login should not have error")

	suite.NotNil(loginResponse.Response.Data, "Login response should have data")
	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	suite.NotEmpty(accessToken, "Access token should not be empty")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access user info before revoke all")
	suite.Nil(userResponse.Response.Error, "Should not have error accessing user info before revoke all")

	revokeAllHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	revokeAllResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions", nil, revokeAllHeaders)
	suite.Equal(200, revokeAllResponse.ResponseRecorder.Code, "Revoke all sessions should succeed")
	suite.Nil(revokeAllResponse.Response.Error, "Revoke all sessions should not have error")

	userResponseAfterRevokeAll := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponseAfterRevokeAll.ResponseRecorder.Code, "Should return 401 after revoke all")
	suite.NotNil(userResponseAfterRevokeAll.Response.Error, "Should have error after revoke all sessions")
}

func (suite *SessionManagementTestSuite) TestAdminRevokeUserSession() {
	email := "admin-revoke-session@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Password login should succeed")
	suite.Nil(loginResponse.Response.Error, "Password login should not have error")

	suite.NotNil(loginResponse.Response.Data, "Login response should have data")
	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	sessionId := session["id"].(string)
	user := session["user"].(map[string]any)
	userId := user["id"].(string)
	suite.NotEmpty(accessToken, "Access token should not be empty")
	suite.NotEmpty(sessionId, "Session ID should not be empty")
	suite.NotEmpty(userId, "User ID should not be empty")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access user info before admin revoke")
	suite.Nil(userResponse.Response.Error, "Should not have error accessing user info before admin revoke")

	adminRevokeHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	adminRevokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/admin/sessions/"+sessionId, nil, adminRevokeHeaders)
	suite.Equal(200, adminRevokeResponse.ResponseRecorder.Code, "Admin session revoke should succeed")
	suite.Nil(adminRevokeResponse.Response.Error, "Admin session revoke should not have error")

	userResponseAfterAdminRevoke := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponseAfterAdminRevoke.ResponseRecorder.Code, "Should return 401 after admin revoke")
	suite.NotNil(userResponseAfterAdminRevoke.Response.Error, "Should have error after admin session revoke")
}

func (suite *SessionManagementTestSuite) TestAdminRevokeAllUserSessions() {
	email := "admin-revoke-all-sessions@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Password login should succeed")
	suite.Nil(loginResponse.Response.Error, "Password login should not have error")

	suite.NotNil(loginResponse.Response.Data, "Login response should have data")
	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	user := session["user"].(map[string]any)
	userId := user["id"].(string)
	suite.NotEmpty(accessToken, "Access token should not be empty")
	suite.NotEmpty(userId, "User ID should not be empty")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Should be able to access user info before admin revoke all")
	suite.Nil(userResponse.Response.Error, "Should not have error accessing user info before admin revoke all")

	adminRevokeAllHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	adminRevokeAllResponse := suite.helper.MakeDELETERequest(suite.T(), "/admin/users/"+userId+"/sessions", nil, adminRevokeAllHeaders)
	suite.Equal(200, adminRevokeAllResponse.ResponseRecorder.Code, "Admin revoke all user sessions should succeed")
	suite.Nil(adminRevokeAllResponse.Response.Error, "Admin revoke all user sessions should not have error")

	userResponseAfterAdminRevokeAll := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponseAfterAdminRevokeAll.ResponseRecorder.Code, "Should return 401 after admin revoke all")
	suite.NotNil(userResponseAfterAdminRevokeAll.Response.Error, "Should have error after admin revoke all user sessions")
}

func TestSessionManagementTestSuite(t *testing.T) {
	suite.Run(t, new(SessionManagementTestSuite))
}
