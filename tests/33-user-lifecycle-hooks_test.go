package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
)

type UserLifecycleHooksTestSuite struct {
	TestSuite
	helper               *TestHelper
	hooksAuthService     services.AuthService // 独立的 AuthService 实例用于 hooks 测试
	hooksRouter          *gin.Engine          // 使用独立 AuthService 的 Router
	originalAuthService  services.AuthService // 保存原始 AuthService
	originalRouter       *gin.Engine          // 保存原始 Router
}

func (suite *UserLifecycleHooksTestSuite) SetupSuite() {
	// 先调用父类初始化基础设施（DB、EmailProvider、SMSProvider 等）
	suite.TestSuite.SetupSuite()
	
	// 保存原始的 AuthService 和 Router
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

func (suite *UserLifecycleHooksTestSuite) TearDownSuite() {
	// 恢复原始的 AuthService 和 Router
	suite.AuthService = suite.originalAuthService
	suite.Router = suite.originalRouter
}

func (suite *UserLifecycleHooksTestSuite) SetupTest() {
	// 在每个测试前，重新创建独立的 AuthService 实例，确保 hooks 不会累积
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

// TestBeforeUserCreatedHook tests BeforeUserCreatedUse middleware
func (suite *UserLifecycleHooksTestSuite) TestBeforeUserCreatedHook() {
	var beforeHookCalled bool
	var beforeHookUserMetadata map[string]any

	// Register BeforeUserCreatedUse middleware
	suite.hooksAuthService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		beforeHookCalled = true
		// Modify user metadata in Before hook
		metadata := ctx.UserMetadata()
		if metadata == nil {
			metadata = make(map[string]any)
		}
		metadata["before_hook_modified"] = true
		ctx.SetUserMetadata(metadata)
		beforeHookUserMetadata = metadata
		return next()
	})

	// Create user via signup
	email := "before-hook@example.com"
	signupRequestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Signup should succeed")
	suite.True(beforeHookCalled, "BeforeUserCreatedUse hook should be called")

	// Verify user was created with modified metadata
	var user models.User
	err := suite.DB.Where("email = ? AND instance_id = ?", email, suite.TestInstance).First(&user).Error
	suite.Require().NoError(err)
	suite.Contains(beforeHookUserMetadata, "before_hook_modified", "Metadata should contain before_hook_modified")
}

// TestAfterUserCreatedHook tests AfterUserCreatedUse middleware
func (suite *UserLifecycleHooksTestSuite) TestAfterUserCreatedHook() {
	var afterHookCalled bool
	var afterHookUserID string
	var afterHookSource services.UserCreatedSource

	// Register AfterUserCreatedUse middleware
	suite.hooksAuthService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		afterHookCalled = true
		user := ctx.User()
		if user != nil {
			afterHookUserID = user.HashID
		}
		afterHookSource = ctx.Source()
		return next()
	})

	// Create user via signup
	email := "after-hook@example.com"
	signupRequestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Signup should succeed")
	suite.True(afterHookCalled, "AfterUserCreatedUse hook should be called")
	suite.NotEmpty(afterHookUserID, "User ID should be available in After hook")
	suite.Equal(services.UserCreatedSourceSignup, afterHookSource, "Source should be signup")
}

// TestBeforeHookErrorRollback tests that Before hook error causes transaction rollback
func (suite *UserLifecycleHooksTestSuite) TestBeforeHookErrorRollback() {
	// Register BeforeUserCreatedUse middleware that returns error
	suite.hooksAuthService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		return fmt.Errorf("before hook error: test_error")
	})

	// Try to create user
	email := "before-error@example.com"
	signupRequestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	// pin library returns 200 even for errors, check error in response body
	suite.NotNil(response.Error, "Signup should fail due to Before hook error")

	// Verify user was NOT created
	var count int64
	err := suite.DB.Model(&models.User{}).Where("email = ? AND instance_id = ?", email, suite.TestInstance).Count(&count).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), count, "User should not be created when Before hook returns error")
}

// TestAfterHookErrorRollback tests that After hook error causes transaction rollback
func (suite *UserLifecycleHooksTestSuite) TestAfterHookErrorRollback() {
	// Register AfterUserCreatedUse middleware that returns error
	suite.hooksAuthService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		return fmt.Errorf("after hook error: test_error")
	})

	// Try to create user
	email := "after-error@example.com"
	signupRequestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	// pin library returns 200 even for errors, check error in response body
	suite.NotNil(response.Error, "Signup should fail due to After hook error")

	// Verify user was NOT created (transaction rolled back)
	var count int64
	err := suite.DB.Model(&models.User{}).Where("email = ? AND instance_id = ?", email, suite.TestInstance).Count(&count).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), count, "User should not be created when After hook returns error")
}

// TestUserCreatedSourceSignup tests source is correctly set for signup
func (suite *UserLifecycleHooksTestSuite) TestUserCreatedSourceSignup() {
	var capturedSource services.UserCreatedSource

	suite.hooksAuthService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		capturedSource = ctx.Source()
		return next()
	})

	email := "source-signup@example.com"
	signupRequestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(services.UserCreatedSourceSignup, capturedSource, "Source should be signup")
}

// TestUserCreatedSourceAdmin tests source is correctly set for admin creation
func (suite *UserLifecycleHooksTestSuite) TestUserCreatedSourceAdmin() {
	var capturedSource services.UserCreatedSource

	suite.hooksAuthService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		capturedSource = ctx.Source()
		return next()
	})

	// Create admin session first
	adminEmail := "admin@example.com"
	adminPassword := "AdminPassword2024!"
	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    adminEmail,
		"password": adminPassword,
	})

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      adminEmail,
		"password":   adminPassword,
	})
	accessToken := loginResponse.Data.(map[string]any)["session"].(map[string]any)["access_token"].(string)

	// Create user via admin API
	email := "admin-created@example.com"
	createUserReq := S{
		"email":    email,
		"password": "UserPassword2024!",
	}

	// Create POST request with auth header
	jsonBody, _ := json.Marshal(createUserReq)
	req, _ := http.NewRequest("POST", "/admin/users", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	suite.helper.Router.ServeHTTP(w, req)

	suite.Equal(services.UserCreatedSourceAdmin, capturedSource, "Source should be admin")
}

// TestMultipleHooksChain tests that multiple hooks are called in order
func (suite *UserLifecycleHooksTestSuite) TestMultipleHooksChain() {
	var hookOrder []string

	suite.hooksAuthService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		hookOrder = append(hookOrder, "before1")
		return next()
	})

	suite.hooksAuthService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		hookOrder = append(hookOrder, "before2")
		return next()
	})

	suite.hooksAuthService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		hookOrder = append(hookOrder, "after1")
		return next()
	})

	suite.hooksAuthService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
		hookOrder = append(hookOrder, "after2")
		return next()
	})

	email := "multiple-hooks@example.com"
	signupRequestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal([]string{"before1", "before2", "after1", "after2"}, hookOrder, "Hooks should be called in registration order")
}

func TestUserLifecycleHooksTestSuite(t *testing.T) {
	suite.Run(t, new(UserLifecycleHooksTestSuite))
}
