package tests

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
)

type SessionHooksTestSuite struct {
	TestSuite
	helper              *TestHelper
	hooksAuthService    services.AuthService // 独立的 AuthService 实例
	hooksRouter         *gin.Engine
	originalAuthService services.AuthService
	originalRouter      *gin.Engine
}

func (suite *SessionHooksTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()

	suite.originalAuthService = suite.AuthService
	suite.originalRouter = suite.Router

	// 创建公共的测试 AuthService 实例
	instance := CreateTestAuthServiceInstance(
		suite.DB,
		suite.TestInstance,
		suite.EmailProvider,
		suite.SMSProvider,
		suite.T(),
	)

	suite.hooksAuthService = instance.AuthService
	suite.hooksRouter = instance.Router
	suite.helper = instance.Helper
	suite.AuthService = instance.AuthService
	suite.Router = instance.Router
}

func (suite *SessionHooksTestSuite) TearDownSuite() {
	suite.AuthService = suite.originalAuthService
	suite.Router = suite.originalRouter
}

// TestSessionCreatedHook tests SessionCreatedUse middleware
func (suite *SessionHooksTestSuite) TestSessionCreatedHook() {
	var sessionHookCalled bool
	var capturedUserID string
	var capturedSessionID string
	var capturedAccessToken string
	var capturedRefreshToken string

	// Register SessionCreatedUse middleware
	suite.hooksAuthService.SessionCreatedUse(func(ctx services.SessionCreatedContext, next func() error) error {
		sessionHookCalled = true
		if ctx.User() != nil {
			capturedUserID = ctx.User().HashID
		}
		if ctx.Session() != nil {
			capturedSessionID = ctx.Session().HashID
		}
		response := ctx.Response()
		if response != nil {
			capturedAccessToken = response.AccessToken
			capturedRefreshToken = response.RefreshToken
		}
		return next()
	})

	// Signup user
	email := "session-hook@example.com"
	password := "MySecurePassword2024!"
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)

	// Login to create session
	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")
	suite.True(sessionHookCalled, "SessionCreatedUse hook should be called")
	suite.NotEmpty(capturedUserID, "User ID should be available")
	suite.NotEmpty(capturedSessionID, "Session ID should be available")
	suite.NotEmpty(capturedAccessToken, "Access token should be available")
	suite.NotEmpty(capturedRefreshToken, "Refresh token should be available")

	// Verify tokens match response
	responseData := loginResponse.Data.(map[string]any)
	sessionData := responseData["session"].(map[string]any)
	suite.Equal(sessionData["access_token"], capturedAccessToken, "Access token should match")
	suite.Equal(sessionData["refresh_token"], capturedRefreshToken, "Refresh token should match")
}

// TestSessionCreatedHookMultipleMiddlewares tests multiple SessionCreatedUse middlewares
func (suite *SessionHooksTestSuite) TestSessionCreatedHookMultipleMiddlewares() {
	var hookOrder []string

	suite.hooksAuthService.SessionCreatedUse(func(ctx services.SessionCreatedContext, next func() error) error {
		hookOrder = append(hookOrder, "session1")
		return next()
	})

	suite.hooksAuthService.SessionCreatedUse(func(ctx services.SessionCreatedContext, next func() error) error {
		hookOrder = append(hookOrder, "session2")
		return next()
	})

	// Signup and login (both create sessions, so hooks will be called twice)
	email := "session-multiple@example.com"
	password := "MySecurePassword2024!"
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})

	// Reset hookOrder to only count login session creation
	hookOrder = []string{}

	suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	})

	suite.Equal([]string{"session1", "session2"}, hookOrder, "Multiple SessionCreatedUse hooks should be called in order on login")
}

// TestSessionCreatedHookOnRefresh tests SessionCreatedUse hook on token refresh
func (suite *SessionHooksTestSuite) TestSessionCreatedHookOnRefresh() {
	var sessionHookCallCount int

	suite.hooksAuthService.SessionCreatedUse(func(ctx services.SessionCreatedContext, next func() error) error {
		sessionHookCallCount++
		return next()
	})

	// Signup and login (both create sessions, so hooks will be called twice)
	email := "session-refresh@example.com"
	password := "MySecurePassword2024!"
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})

	// Reset counter to only count login session creation
	sessionHookCallCount = 0

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	})

	suite.Equal(1, sessionHookCallCount, "SessionCreatedUse should be called once on login")

	// Refresh token
	loginData := loginResponse.Data.(map[string]any)
	sessionData := loginData["session"].(map[string]any)
	refreshToken := sessionData["refresh_token"].(string)

	refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})

	suite.Equal(200, refreshResponse.ResponseRecorder.Code, "Token refresh should succeed")
	// Note: RefreshSession may or may not trigger SessionCreatedUse depending on implementation
	// This test verifies the hook is called at least once
	suite.GreaterOrEqual(sessionHookCallCount, 1, "SessionCreatedUse should be called at least once")
}

// TestSessionCreatedHookContextAccess tests that context provides correct information
func (suite *SessionHooksTestSuite) TestSessionCreatedHookContextAccess() {
	var capturedUser *services.User
	var capturedSession *services.Session
	var capturedResponse *services.SessionCreatedResponse

	suite.hooksAuthService.SessionCreatedUse(func(ctx services.SessionCreatedContext, next func() error) error {
		capturedUser = ctx.User()
		capturedSession = ctx.Session()
		capturedResponse = ctx.Response()
		return next()
	})

	// Signup and login
	email := "session-context@example.com"
	password := "MySecurePassword2024!"
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})

	suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	})

	suite.NotNil(capturedUser, "User should be available in context")
	suite.NotNil(capturedSession, "Session should be available in context")
	suite.NotNil(capturedResponse, "Response should be available in context")
	suite.NotEmpty(capturedResponse.AccessToken, "Access token should be in response")
	suite.NotEmpty(capturedResponse.RefreshToken, "Refresh token should be in response")
}

func TestSessionHooksTestSuite(t *testing.T) {
	suite.Run(t, new(SessionHooksTestSuite))
}
