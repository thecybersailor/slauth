package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type SignupAndUserQueriesTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SignupAndUserQueriesTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestDomain, suite.EmailProvider, suite.SMSProvider)

	// Set default config: email confirmation enabled
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"confirm_email": true,
		},
	}, nil)
	suite.Require().Equal(200, configResponse.ResponseRecorder.Code, "Failed to set default config")
}

// Test case corresponds to frontend code:
// API Implementation: packages/slauth-ts/src/AiraAuthClient.ts - signUp() method
// Type Definitions: packages/slauth-ts/src/lib/types.ts - SignUpWithPasswordCredentials, AuthResponsePassword
func (suite *SignupAndUserQueriesTestSuite) TestSignup() {
	email := "test@example.com"

	var countBefore int64
	err := suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND domain_code = ?", email, suite.TestDomain).Scan(&countBefore).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), countBefore, "User should not exist before signup")

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	response.Print()

	responseData := response.Response.Data.(map[string]any)
	userInfo := responseData["user"].(map[string]any)
	suite.Equal(email, userInfo["email"], "User email should match")
	suite.NotEmpty(userInfo["id"], "User ID should not be empty")
	suite.Nil(responseData["session"], "Session should be nil for unconfirmed user")

	var countAfter int64
	err = suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND domain_code = ?", email, suite.TestDomain).Scan(&countAfter).Error
	suite.Require().NoError(err)
	suite.Equal(int64(1), countAfter, "User should exist after signup")

	var user struct {
		Email      string
		DomainCode string
		CreatedAt  string
	}
	err = suite.DB.Raw("SELECT email, domain_code, created_at FROM users WHERE email = ? AND domain_code = ?", email, suite.TestDomain).Scan(&user).Error
	suite.Require().NoError(err)
	suite.Equal(email, user.Email, "User email should match")
	suite.Equal(suite.TestDomain, user.DomainCode, "User domain should match")
	suite.NotEmpty(user.CreatedAt, "User created_at should not be empty")
}

// Test case corresponds to frontend code:
// API Implementation: packages/slauth-ts/src/AiraAuthClient.ts - signUp() method
// Type Definitions: packages/slauth-ts/src/lib/types.ts - AuthResponsePassword, WeakPassword
func (suite *SignupAndUserQueriesTestSuite) TestSignupWithWeakPassword() {
	email := "weak@example.com"

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "123",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)

	suite.helper.HasError(suite.T(), response, "weak_password", "Weak password should be rejected")
}

// Test case corresponds to frontend code:
// API Implementation: packages/slauth-ts/src/AiraAuthClient.ts - signUp() method
// Type Definitions: packages/slauth-ts/src/lib/types.ts - SignUpWithPasswordCredentials, AuthResponsePassword
// Error Handling: packages/slauth-ts/src/lib/errors.ts - AuthError type
func (suite *SignupAndUserQueriesTestSuite) TestSignupDuplicateEmail() {
	email := "duplicate@example.com"

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response1 := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	suite.Equal(200, response1.ResponseRecorder.Code, "First signup should succeed")

	response2 := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)

	suite.helper.HasError(suite.T(), response2, "user_already_exists", "Duplicate email should be rejected")
}

// Test case corresponds to frontend code:
// API Implementation: packages/slauth-ts/src/AiraAuthClient.ts - signUp() method
// Type Definitions: packages/slauth-ts/src/lib/types.ts - SignUpWithPasswordCredentials, AuthResponsePassword
// Error Handling: packages/slauth-ts/src/lib/errors.ts - AuthError type
func (suite *SignupAndUserQueriesTestSuite) TestSignupInvalidEmail() {

	requestBody := map[string]interface{}{
		"email":    "invalid-email",
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)

	suite.helper.HasError(suite.T(), response, "email_address_invalid", "Invalid email should be rejected")
}

// Test case corresponds to frontend code:
// API Implementation: packages/slauth-ts/src/AiraAuthClient.ts - signUp() method
// Type Definitions: packages/slauth-ts/src/lib/types.ts - SignUpWithPasswordCredentials, AuthResponsePassword
// Error Handling: packages/slauth-ts/src/lib/errors.ts - AuthError type
func (suite *SignupAndUserQueriesTestSuite) TestSignupMissingPassword() {
	email := "nopassword@example.com"

	requestBody := map[string]interface{}{
		"email": email,
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)

	responseData := response.Response.Data.(map[string]any)
	userInfo := responseData["user"].(map[string]any)
	suite.Equal(email, userInfo["email"], "User email should match")
	suite.NotEmpty(userInfo["id"], "User ID should not be empty")
	suite.Nil(responseData["session"], "Session should be nil for unconfirmed user")
}

// Test case corresponds to frontend code:
// API Implementation: packages/slauth-ts/src/AdminApi.ts - listUsers() method
// Type Definitions: packages/slauth-ts/src/lib/types.ts - AdminListUsersRequest, AdminListUsersResponse
func (suite *SignupAndUserQueriesTestSuite) TestListUsers() {
	users := []map[string]interface{}{
		{"email": "listuser1@example.com", "password": "MySecurePassword2024!"},
		{"email": "listuser2@example.com", "password": "MySecurePassword2024!"},
		{"email": "listuser3@example.com", "password": "MySecurePassword2024!"},
	}

	for _, user := range users {
		response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", user)
		suite.Equal(200, response.ResponseRecorder.Code, "User signup should succeed")
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	})

	suite.T().Logf("Response status: %d", response.ResponseRecorder.Code)
	suite.T().Logf("Response body: %s", response.ResponseRecorder.Body.String())

	response.Print()

	responseData := response.Response.Data.(map[string]any)
	usersInterface := responseData["users"].([]any)

	totalCount := responseData["total"].(float64)
	suite.GreaterOrEqual(totalCount, float64(3), "Should have at least 3 users")
	suite.Equal(float64(1), responseData["page"], "Page should be 1")
	suite.Equal(float64(20), responseData["page_size"], "Page size should be 20")

	var foundUsers []map[string]any
	for _, userInterface := range usersInterface {
		user := userInterface.(map[string]any)
		email := user["email"].(string)
		if email == "listuser1@example.com" || email == "listuser2@example.com" || email == "listuser3@example.com" {
			foundUsers = append(foundUsers, user)
		}
	}

	suite.Equal(3, len(foundUsers), "Should find all 3 created users")

	for _, user := range foundUsers {
		suite.Equal(false, user["email_confirmed"], "User email should not be confirmed")
		suite.Equal(false, user["phone_confirmed"], "User phone should not be confirmed")
		suite.Equal(false, user["is_anonymous"], "User should not be anonymous")
		suite.NotEmpty(user["id"], "User should have a hashid")
		suite.NotEmpty(user["created_at"], "User should have created_at")
		suite.NotEmpty(user["updated_at"], "User should have updated_at")
	}

	response = suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"pagination": S{
			"page":     1,
			"pageSize": 2,
		},
	})

	responseData = response.Response.Data.(map[string]any)
	suite.GreaterOrEqual(responseData["total"].(float64), float64(2), "Should have at least 2 users for pagination test")
	suite.Equal(float64(1), responseData["page"], "Page should be 1")
	suite.Equal(float64(2), responseData["page_size"], "Page size should be 2")

	usersInterface = responseData["users"].([]any)
	suite.Equal(2, len(usersInterface), "Should return exactly 2 users")

	response = suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"filters": S{
			"email": S{
				"$eq": "listuser1@example.com",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	})

	responseData = response.Response.Data.(map[string]any)
	suite.Equal(float64(1), responseData["total"], "Filtered total should be 1")

	usersInterface = responseData["users"].([]any)
	suite.Equal(1, len(usersInterface), "Should return exactly 1 user")
	user := usersInterface[0].(map[string]any)
	suite.Equal("listuser1@example.com", user["email"], "Should return the filtered user")
}

func (suite *SignupAndUserQueriesTestSuite) TestGetUser() {
	email := "getuser@example.com"
	requestBody := S{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Signup should succeed")

	responseData := response.Response.Data.(map[string]any)
	userInfo := responseData["user"].(map[string]any)
	userID := userInfo["id"].(string)
	suite.NotEmpty(userID, "User ID should not be empty")

	response = suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, response.ResponseRecorder.Code, "Get user should succeed")

	responseData = response.Response.Data.(map[string]any)
	suite.Equal(userID, responseData["id"], "User ID should match")
	suite.Equal(email, responseData["email"], "Email should match")
	suite.Equal(false, responseData["email_confirmed"], "Email should not be confirmed")
	suite.Equal(false, responseData["phone_confirmed"], "Phone should not be confirmed")
	suite.Equal(false, responseData["is_anonymous"], "User should not be anonymous")
	suite.NotEmpty(responseData["created_at"], "Created at should be present")
	suite.NotEmpty(responseData["updated_at"], "Updated at should be present")

	nonExistentHashID := "xdJqG1Dl4EgZvzPa9Y"
	response = suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+nonExistentHashID)
	suite.Equal(200, response.ResponseRecorder.Code, "Should return 200 with error in body")
	suite.helper.HasError(suite.T(), response, "user_not_found", "Should return user_not_found error for non-existent user")

	response = suite.helper.MakeGETRequest(suite.T(), "/admin/users/invalid-id-format")
	suite.Equal(200, response.ResponseRecorder.Code, "Should return 200 with error in body")
	suite.helper.HasError(suite.T(), response, "user_not_found", "Should return user_not_found error for invalid ID format")
}

func (suite *SignupAndUserQueriesTestSuite) TestGetUserStats() {
	emails := []string{"stats1@example.com", "stats2@example.com", "stats3@example.com"}
	for _, email := range emails {
		requestBody := S{
			"email":    email,
			"password": "MySecurePassword2024!",
		}
		response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
		suite.Equal(200, response.ResponseRecorder.Code, "Signup should succeed for "+email)
	}

	response := suite.helper.MakeGETRequest(suite.T(), "/admin/stats/users")
	suite.Equal(200, response.ResponseRecorder.Code, "Get user stats should succeed")

	responseData := response.Response.Data.(map[string]any)
	count := responseData["count"]
	suite.NotNil(count, "Count should be present")

	switch v := count.(type) {
	case float64:
		suite.GreaterOrEqual(v, float64(3), "Should have at least 3 users")
	case int:
		suite.GreaterOrEqual(v, 3, "Should have at least 3 users")
	case int64:
		suite.GreaterOrEqual(v, int64(3), "Should have at least 3 users")
	default:
		suite.Fail("Count should be a number", "Got type %T with value %v", v, v)
	}
}

func (suite *SignupAndUserQueriesTestSuite) TestGetRecentSignups() {
	emails := []string{"recent1@example.com", "recent2@example.com", "recent3@example.com"}
	for _, email := range emails {
		requestBody := S{
			"email":    email,
			"password": "MySecurePassword2024!",
		}
		response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
		suite.Equal(200, response.ResponseRecorder.Code, "Signup should succeed for "+email)
	}

	response := suite.helper.MakeGETRequest(suite.T(), "/admin/stats/recent-signups?days=7")
	suite.Equal(200, response.ResponseRecorder.Code, "Get recent signups should succeed")

	suite.T().Logf("Response status: %d", response.ResponseRecorder.Code)
	suite.T().Logf("Response body: %s", response.ResponseRecorder.Body.String())
	suite.T().Logf("Response.Data: %+v", response.Response.Data)

	if response.Response.Data == nil {
		suite.Fail("Response data is nil")
	}

	responseData, ok := response.Response.Data.(map[string]any)
	if !ok {
		suite.T().Logf("Response data type: %T", response.Response.Data)
		suite.Fail("Failed to cast response data to map[string]any")
	}
	suite.NotNil(responseData, "Response data should not be nil")

	usersInterface, ok := responseData["users"].([]any)
	if !ok {
		suite.T().Logf("Response data: %+v", responseData)
		suite.Fail("Failed to cast users to []any")
	}

	suite.GreaterOrEqual(len(usersInterface), 3, "Should have at least 3 recent signups")

	for _, userInterface := range usersInterface {
		user := userInterface.(map[string]any)
		suite.NotEmpty(user["id"], "User should have an ID")
		suite.NotEmpty(user["email"], "User should have an email")
		suite.NotEmpty(user["created_at"], "User should have created_at")
	}

	suite.Equal(float64(1), responseData["page"], "Page should be 1")
	suite.Equal(float64(3), responseData["page_size"], "Page size should equal total users")
}

// Test case verifies that when email confirmation is disabled:
// - User can signup and immediately get a session without email confirmation
// - Tokens (access_token, refresh_token) are returned in the response
// - email_confirmed_at remains NULL (not requiring confirmation ≠ auto-confirmed)
func (suite *SignupAndUserQueriesTestSuite) TestSignupWithoutEmailConfirmation() {
	email := "noconfirm@example.com"

	// Disable email confirmation for this test (default is enabled by SetupSuite)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"confirm_email": false,
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")
	suite.T().Logf("Config updated to disable email confirmation")

	// Verify config was updated by reading it back
	getConfigResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	suite.T().Logf("Current config after update: %+v", getConfigResponse.Response.Data)

	// Signup request with redirect parameter
	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
		"options": map[string]interface{}{
			"redirect_to": "/dashboard",
		},
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	response.Print()

	// Verify response structure
	responseData := response.Response.Data.(map[string]any)

	// User should be created
	userInfo := responseData["user"].(map[string]any)
	suite.Equal(email, userInfo["email"], "User email should match")
	suite.NotEmpty(userInfo["id"], "User ID should not be empty")

	// Session should be created automatically when confirm_email=false
	session := responseData["session"]
	suite.NotNil(session, "Session should be created when email confirmation is disabled")

	if session != nil {
		sessionData := session.(map[string]any)
		suite.NotEmpty(sessionData["access_token"], "Access token should be present")
		suite.NotEmpty(sessionData["refresh_token"], "Refresh token should be present")
		suite.Equal("Bearer", sessionData["token_type"], "Token type should be Bearer")
		suite.NotEmpty(sessionData["expires_in"], "Expires in should be present")
		suite.T().Logf("Session created successfully with access_token: %s...", sessionData["access_token"].(string)[:10])
	}

	// RedirectTo validation may fail if URL is not whitelisted, this is expected
	redirectTo := responseData["redirect_to"]
	if redirectTo != nil && redirectTo.(string) != "" {
		suite.T().Logf("Redirect URL returned: %s", redirectTo.(string))
	} else {
		suite.T().Logf("Redirect URL validation failed (expected if /dashboard is not in whitelist)")
	}

	// Verify user exists in database
	var user struct {
		Email            string
		EmailConfirmedAt *time.Time
		DomainCode       string
	}
	err := suite.DB.Raw("SELECT email, email_confirmed_at, domain_code FROM users WHERE email = ? AND domain_code = ?", email, suite.TestDomain).Scan(&user).Error
	suite.Require().NoError(err)
	suite.Equal(email, user.Email, "User email should match")
	suite.Equal(suite.TestDomain, user.DomainCode, "User domain should match")

	// When confirm_email is disabled, email_confirmed_at remains NULL
	// The user can login immediately without confirmation, but the confirmation status is not automatically set
	suite.Nil(user.EmailConfirmedAt, "Email confirmation status should remain NULL when confirm_email is disabled")
	suite.T().Logf("User created without email confirmation requirement")

	// Restore email confirmation setting
	restoreResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"confirm_email": true,
		},
	}, nil)
	suite.Equal(200, restoreResponse.ResponseRecorder.Code, "Config restore should succeed")
}

// Test case verifies GetCurrentUser functionality:
// - User can signup and signin to get access token
// - With valid token, /auth/user endpoint uses GetCurrentUser to retrieve user info
// - Without token, request should fail with 401
// - With invalid token, request should fail with 401
func (suite *SignupAndUserQueriesTestSuite) TestGetCurrentUser() {
	email := "getcurrentuser@example.com"
	password := "MySecurePassword2024!"

	// Disable email confirmation for immediate signin
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"confirm_email": false,
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// Signup user
	signupBody := S{
		"email":    email,
		"password": password,
	}
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	// Get access token from signup response
	signupData := signupResponse.Response.Data.(map[string]any)
	sessionData := signupData["session"].(map[string]any)
	accessToken := sessionData["access_token"].(string)
	suite.NotEmpty(accessToken, "Access token should be present")

	// Test 1: Get current user with valid token (uses GetCurrentUser internally)
	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user should succeed with valid token")
	suite.Nil(userResponse.Response.Error, "Get user should not have error")

	userData := userResponse.Response.Data.(map[string]any)
	userInfo := userData["user"].(map[string]any)
	suite.Equal(email, userInfo["email"], "User email should match")
	suite.NotEmpty(userInfo["id"], "User ID should not be empty")

	// Test 2: Get current user without token (should fail)
	unauthorizedResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/user")
	suite.Equal(401, unauthorizedResponse.ResponseRecorder.Code, "Get user should fail without token")

	// Test 3: Get current user with invalid token (should fail)
	invalidTokenResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", "invalid-token-12345")
	suite.Equal(401, invalidTokenResponse.ResponseRecorder.Code, "Get user should fail with invalid token")

	// Restore email confirmation setting
	restoreResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"confirm_email": true,
		},
	}, nil)
	suite.Equal(200, restoreResponse.ResponseRecorder.Code, "Config restore should succeed")
}

func TestSignupAndUserQueriesTestSuite(t *testing.T) {
	suite.Run(t, new(SignupAndUserQueriesTestSuite))
}
