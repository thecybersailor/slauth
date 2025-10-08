package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/consts"
)

type SigninQueriesTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SigninQueriesTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

func (suite *SigninQueriesTestSuite) TestGetUserInfo() {
	email := "get-user-info@example.com"
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
	sessionInfo := responseData["session"].(map[string]any)
	accessToken := sessionInfo["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user info should succeed")
	suite.Nil(userResponse.Response.Error, "Get user info should not have error")

	suite.NotNil(userResponse.Response.Data, "User response should have data")
	userData := userResponse.Response.Data.(map[string]any)
	suite.NotNil(userData["user"], "Should have user object")

	user := userData["user"].(map[string]any)
	suite.Equal(email, user["email"], "User email should match")
	suite.NotEmpty(user["id"], "User should have ID")
	suite.NotEmpty(user["created_at"], "User should have created_at")
	suite.NotEmpty(user["updated_at"], "User should have updated_at")

	suite.T().Log("✅ Get user info test completed successfully")
}

func (suite *SigninQueriesTestSuite) TestGetUserInfoWithoutToken() {
	userResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/user")
	suite.helper.IsError(suite.T(), userResponse, consts.NO_AUTHORIZATION)
}

func (suite *SigninQueriesTestSuite) TestGetUserInfoWithInvalidToken() {
	invalidToken := "invalid.jwt.token"
	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", invalidToken)
	suite.helper.IsError(suite.T(), userResponse, consts.BAD_JWT)
}

func (suite *SigninQueriesTestSuite) TestListAllSessions() {
	email := "list-sessions@example.com"
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
	sessionInfo := responseData["session"].(map[string]any)
	accessToken := sessionInfo["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	sessionsResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/admin/sessions", accessToken)
	suite.Equal(200, sessionsResponse.ResponseRecorder.Code, "List all sessions should succeed")
	suite.Nil(sessionsResponse.Response.Error, "List all sessions should not have error")

	suite.NotNil(sessionsResponse.Response.Data, "Sessions response should have data")
	sessionsData := sessionsResponse.Response.Data.(map[string]any)

	suite.Contains(sessionsData, "sessions", "Should have sessions array")
	suite.Contains(sessionsData, "total", "Should have total count")
	suite.Contains(sessionsData, "page", "Should have page number")
	suite.Contains(sessionsData, "page_size", "Should have page size")

	sessions := sessionsData["sessions"].([]any)
	suite.GreaterOrEqual(len(sessions), 1, "Should have at least one session")

	if len(sessions) > 0 {
		session := sessions[0].(map[string]any)
		suite.Contains(session, "id", "Session should have ID")
		suite.Contains(session, "user_id", "Session should have user_id")
		suite.Contains(session, "created_at", "Session should have created_at")
		suite.Contains(session, "updated_at", "Session should have updated_at")
	}

	suite.T().Log("✅ List all sessions test completed successfully")
}

func (suite *SigninQueriesTestSuite) TestGetActiveSessionStats() {
	email := "session-stats@example.com"
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
	sessionInfo := responseData["session"].(map[string]any)
	accessToken := sessionInfo["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	statsResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/admin/stats/sessions", accessToken)
	suite.Equal(200, statsResponse.ResponseRecorder.Code, "Get session stats should succeed")
	suite.Nil(statsResponse.Response.Error, "Get session stats should not have error")

	suite.NotNil(statsResponse.Response.Data, "Stats response should have data")
	statsData := statsResponse.Response.Data.(map[string]any)

	suite.Contains(statsData, "total_sessions", "Should have total_sessions")
	suite.Contains(statsData, "active_sessions", "Should have active_sessions")
	suite.Contains(statsData, "expired_sessions", "Should have expired_sessions")

	totalSessions := statsData["total_sessions"]
	activeSessions := statsData["active_sessions"]
	expiredSessions := statsData["expired_sessions"]

	suite.GreaterOrEqual(totalSessions, float64(1), "Should have at least one total session")
	suite.GreaterOrEqual(activeSessions, float64(1), "Should have at least one active session")
	suite.GreaterOrEqual(expiredSessions, float64(0), "Expired sessions should be non-negative")

	suite.T().Log("✅ Get active session stats test completed successfully")
}

func (suite *SigninQueriesTestSuite) TestGetRecentSignins() {
	email := "recent-signins-test@example.com"
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
	sessionInfo := responseData["session"].(map[string]any)
	accessToken := sessionInfo["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	signinsResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/admin/stats/recent-signins", accessToken)
	suite.Equal(200, signinsResponse.ResponseRecorder.Code, "Get recent signins should succeed")
	suite.Nil(signinsResponse.Response.Error, "Get recent signins should not have error")

	suite.NotNil(signinsResponse.Response.Data, "Signins response should have data")
	signinsData := signinsResponse.Response.Data.(map[string]any)

	suite.Contains(signinsData, "recent_signins", "Should have recent_signins array")

	recentSignins := signinsData["recent_signins"].([]any)
	suite.GreaterOrEqual(len(recentSignins), 1, "Should have at least one recent signin")

	if len(recentSignins) > 0 {
		signin := recentSignins[0].(map[string]any)
		suite.Contains(signin, "user_id", "Signin should have user_id")
		suite.Contains(signin, "email", "Signin should have email")
		suite.Contains(signin, "signin_at", "Signin should have signin_at")

		signinEmail := signin["email"].(string)
		suite.NotEmpty(signinEmail, "Signin should have email")
		suite.Contains(signinEmail, "@", "Signin email should be valid")
	}

	suite.T().Log("✅ Get recent signins test completed successfully")
}

func (suite *SigninQueriesTestSuite) TestListUserSessions() {
	email := "list-user-sessions@example.com"
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
	sessionInfo := responseData["session"].(map[string]any)
	accessToken := sessionInfo["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	userInfo := responseData["user"].(map[string]any)
	userID := userInfo["id"].(string)
	suite.NotEmpty(userID, "Should have user ID")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user info should succeed")
	suite.Nil(userResponse.Response.Error, "Get user info should not have error")

	userData := userResponse.Response.Data.(map[string]any)
	user := userData["user"].(map[string]any)
	userHashID := user["id"].(string)
	suite.NotEmpty(userHashID, "Should have user hashid")

	userSessionsResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/admin/users/"+userHashID+"/sessions", accessToken)
	suite.Equal(200, userSessionsResponse.ResponseRecorder.Code, "List user sessions should succeed")
	suite.Nil(userSessionsResponse.Response.Error, "List user sessions should not have error")

	suite.NotNil(userSessionsResponse.Response.Data, "User sessions response should have data")
	sessionsData := userSessionsResponse.Response.Data.(map[string]any)

	suite.Contains(sessionsData, "sessions", "Should have sessions array")
	suite.Contains(sessionsData, "total", "Should have total count")
	suite.Contains(sessionsData, "page", "Should have page number")
	suite.Contains(sessionsData, "page_size", "Should have page size")

	sessions := sessionsData["sessions"].([]any)
	suite.GreaterOrEqual(len(sessions), 1, "Should have at least one session")

	if len(sessions) > 0 {
		session := sessions[0].(map[string]any)
		suite.Contains(session, "id", "Session should have ID")
		suite.Contains(session, "user_id", "Session should have user_id")
		suite.Contains(session, "created_at", "Session should have created_at")
		suite.Contains(session, "updated_at", "Session should have updated_at")

		suite.Equal(userHashID, session["user_id"], "Session user_id should match")
	}

	suite.T().Log("✅ List user sessions test completed successfully")
}

func (suite *SigninQueriesTestSuite) TestGetUserSessions() {
	email := "user-sessions@example.com"
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
	sessionInfo := responseData["session"].(map[string]any)
	accessToken := sessionInfo["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	sessionsResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/sessions", accessToken)
	suite.Equal(200, sessionsResponse.ResponseRecorder.Code, "Get user sessions should succeed")
	suite.Nil(sessionsResponse.Response.Error, "Get user sessions should not have error")

	suite.NotNil(sessionsResponse.Response.Data, "Sessions response should have data")
	sessionsData := sessionsResponse.Response.Data.(map[string]any)

	suite.Contains(sessionsData, "sessions", "Should have sessions array")
	suite.Contains(sessionsData, "total", "Should have total count")
	suite.Contains(sessionsData, "page", "Should have page number")
	suite.Contains(sessionsData, "page_size", "Should have page size")

	sessions := sessionsData["sessions"].([]any)
	suite.GreaterOrEqual(len(sessions), 1, "Should have at least one session")

	if len(sessions) > 0 {
		session := sessions[0].(map[string]any)
		suite.Contains(session, "id", "Session should have ID")
		suite.Contains(session, "user_id", "Session should have user_id")
		suite.Contains(session, "created_at", "Session should have created_at")
		suite.Contains(session, "updated_at", "Session should have updated_at")
	}

	suite.T().Log("✅ Get user sessions test completed successfully")
}

func TestSigninQueriesTestSuite(t *testing.T) {
	suite.Run(t, new(SigninQueriesTestSuite))
}
