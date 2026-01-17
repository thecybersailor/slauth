package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
)

type ServiceConfigTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *ServiceConfigTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// Test case: Enable and disable anonymous sign-ins configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signInAnonymously() method
// Configuration: pkg/config/service.go - AnonymousSignIns field
func (suite *ServiceConfigTestSuite) TestAnonymousSignInConfiguration() {
	// Disable anonymous sign-ins first
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"anonymous_sign_ins": false,
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// Attempt anonymous sign-in when disabled
	anonymousResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"options": S{
			"data": S{
				"is_anonymous": true,
			},
		},
	})

	suite.helper.HasError(suite.T(), anonymousResponse, "anonymous_provider_disabled", "Anonymous sign-in should be rejected when disabled")

	// Enable anonymous sign-ins
	enableResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"anonymous_sign_ins": true,
		},
	}, nil)
	suite.Equal(200, enableResponse.ResponseRecorder.Code, "Config update should succeed")

	// Attempt anonymous sign-in when enabled
	enabledAnonymousResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"options": S{
			"data": S{
				"is_anonymous": true,
			},
		},
	})

	// Anonymous sign-in should succeed when enabled
	suite.Equal(200, enabledAnonymousResponse.ResponseRecorder.Code, "Anonymous sign-in should succeed when enabled")
	if enabledAnonymousResponse.Response.Data != nil {
		responseData := enabledAnonymousResponse.Response.Data.(map[string]interface{})
		sessionData, sessionExists := responseData["session"].(map[string]interface{})
		suite.True(sessionExists, "Session should be present for anonymous sign-in")
		if sessionExists {
			accessToken, tokenExists := sessionData["access_token"].(string)
			suite.True(tokenExists, "Access token should be present")
			suite.NotEmpty(accessToken, "Access token should not be empty")
		}
	}

	// Restore default configuration
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"anonymous_sign_ins": false,
		},
	}, nil)
}

// Test case: Disable new user registration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signUp() method
// Configuration: pkg/config/service.go - AllowNewUsers field
func (suite *ServiceConfigTestSuite) TestAllowNewUsersConfiguration() {
	email := "new-registration-test@example.com"

	// Disable new user registration
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": false,
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// Attempt to sign up when registration is disabled
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": "SecurePassword2024!",
	})

	suite.helper.HasError(suite.T(), signupResponse, "signups_disabled", "Signup should be rejected when AllowNewUsers is false")

	// Verify user was not created in database
	var count int64
	err := suite.DB.Model(&models.User{}).Where("email = ? AND instance_id = ?", email, suite.TestInstance).Count(&count).Error
	suite.NoError(err)
	suite.Equal(int64(0), count, "User should not exist in database when signup is disabled")

	// Re-enable new user registration
	enableResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
		},
	}, nil)
	suite.Equal(200, enableResponse.ResponseRecorder.Code, "Config update should succeed")

	// Attempt to sign up when registration is enabled
	enabledSignupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": "SecurePassword2024!",
	})

	suite.Equal(200, enabledSignupResponse.ResponseRecorder.Code, "Signup should succeed when AllowNewUsers is true")
	suite.helper.MatchObject(suite.T(), enabledSignupResponse, S{
		"user": S{
			"email": email,
		},
	}, "User should be created successfully")

	// Verify user was created in database
	var countAfter int64
	err = suite.DB.Model(&models.User{}).Where("email = ? AND instance_id = ?", email, suite.TestInstance).Count(&countAfter).Error
	suite.NoError(err)
	suite.Equal(int64(1), countAfter, "User should exist in database after signup is enabled")
}

// Test case: Email confirmation requirement configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signUp() and signInWithPassword() methods
// Configuration: pkg/config/service.go - ConfirmEmail field
func (suite *ServiceConfigTestSuite) TestConfirmEmailConfiguration() {
	email := "confirm-email-test@example.com"
	password := "SecurePassword2024!"

	// Enable email confirmation requirement and ensure new users are allowed
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   true,
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// Sign up with email confirmation enabled
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})

	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.NotNil(signupResponse.Response.Data, "Response data should not be nil")
	responseData := signupResponse.Response.Data.(map[string]interface{})
	userInfo := responseData["user"].(map[string]interface{})
	suite.Equal(email, userInfo["email"], "Email should match")
	suite.Nil(responseData["session"], "Session should be nil when email confirmation is required")

	// Attempt to sign in without confirming email
	signinResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	})

	suite.helper.HasError(suite.T(), signinResponse, "email_not_confirmed", "Sign-in should fail when email is not confirmed")

	// Disable email confirmation requirement
	disableConfirmResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)
	suite.Equal(200, disableConfirmResponse.ResponseRecorder.Code, "Config update should succeed")

	// Sign up a new user without email confirmation requirement
	newEmail := "no-confirm-test@example.com"
	noConfirmSignupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    newEmail,
		"password": password,
	})

	suite.Equal(200, noConfirmSignupResponse.ResponseRecorder.Code, "Signup should succeed")
	responseData2 := noConfirmSignupResponse.Response.Data.(map[string]interface{})
	userInfo2 := responseData2["user"].(map[string]interface{})
	suite.Equal(newEmail, userInfo2["email"], "Email should match")

	// Session should be created immediately when email confirmation is not required
	sessionData, sessionExists := responseData2["session"].(map[string]interface{})
	suite.True(sessionExists, "Session should be created immediately")
	if sessionExists {
		accessToken, tokenExists := sessionData["access_token"].(string)
		suite.True(tokenExists, "Access token should be present")
		suite.NotEmpty(accessToken, "Access token should not be empty")
	}
}

func TestServiceConfigSuite(t *testing.T) {
	suite.Run(t, new(ServiceConfigTestSuite))
}
