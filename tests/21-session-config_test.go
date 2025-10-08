package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type SessionConfigTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SessionConfigTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestDomain, suite.EmailProvider, suite.SMSProvider)
}

// Test case: Enforce single session per user configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signInWithPassword() method
// Configuration: pkg/config/session.go - EnforceSingleSessionPerUser field
func (suite *SessionConfigTestSuite) TestEnforceSingleSessionPerUser() {
	email := "single-session-test@example.com"
	password := "SecurePassword2024!"

	// Disable email confirmation for immediate signin
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)

	// Sign up user
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signupResponse.Response.Error, "Signup should succeed")

	// Enable single session per user
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"enforce_single_session_per_user": true,
			},
		},
	}, nil)
	suite.Nil(configResponse.Response.Error, "Config update should succeed")

	// User signs in on device A
	deviceASigninResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(deviceASigninResponse.Response.Error, "Device A signin should succeed")

	deviceAData := deviceASigninResponse.Response.Data.(map[string]interface{})
	deviceASession := deviceAData["session"].(map[string]interface{})
	deviceARefreshToken := deviceASession["refresh_token"].(string)
	suite.NotEmpty(deviceARefreshToken, "Device A should have refresh token")

	// User signs in on device B (same user)
	deviceBSigninResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(deviceBSigninResponse.Response.Error, "Device B signin should succeed")

	deviceBData := deviceBSigninResponse.Response.Data.(map[string]interface{})
	deviceBSession := deviceBData["session"].(map[string]interface{})
	deviceBAccessToken := deviceBSession["access_token"].(string)
	suite.NotEmpty(deviceBAccessToken, "Device B should have access token")

	// Verify device A session is invalidated
	deviceARefreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"refresh_token": deviceARefreshToken,
	})

	suite.helper.HasError(suite.T(), deviceARefreshResponse, "refresh_token_not_found", "Device A session should be terminated")

	// Verify device B session is still active
	deviceBUserResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", deviceBAccessToken)
	suite.Nil(deviceBUserResponse.Response.Error, "Device B session should be active")

	// Disable single session enforcement
	disableResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"enforce_single_session_per_user": false,
			},
		},
	}, nil)
	suite.Nil(disableResponse.Response.Error, "Config update should succeed")

	// Verify multiple sessions can coexist
	multiSession1Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(multiSession1Response.Response.Error, "First session should succeed")

	multiSession1Data := multiSession1Response.Response.Data.(map[string]interface{})
	multiSession1Session := multiSession1Data["session"].(map[string]interface{})
	multiSession1RefreshToken := multiSession1Session["refresh_token"].(string)

	multiSession2Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(multiSession2Response.Response.Error, "Second session should succeed")

	// Verify both sessions are active
	refreshResponse1 := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"refresh_token": multiSession1RefreshToken,
	})
	suite.Equal(200, refreshResponse1.ResponseRecorder.Code, "First session should still be active")
}

// Test case: Time-box user sessions configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - refreshSession() method
// Configuration: pkg/config/session.go - TimeBoxUserSessions field
func (suite *SessionConfigTestSuite) TestTimeBoxUserSessions() {
	email := "timebox-session-test@example.com"
	password := "SecurePassword2024!"

	// Disable email confirmation for immediate signin
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)

	// Sign up user
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signupResponse.Response.Error, "Signup should succeed")

	// Set short time-box (2 seconds for testing)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"time_box_user_sessions": 2, // 2 seconds
			},
		},
	}, nil)
	suite.Nil(configResponse.Response.Error, "Config update should succeed")

	// User signs in
	signinResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signinResponse.Response.Error, "Signin should succeed")

	signinData := signinResponse.Response.Data.(map[string]interface{})
	sessionData := signinData["session"].(map[string]interface{})
	refreshToken := sessionData["refresh_token"].(string)
	suite.NotEmpty(refreshToken, "Should have refresh token")

	// Wait for time-box to expire
	time.Sleep(3 * time.Second)

	// Attempt to refresh token after time-box expiration
	refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"refresh_token": refreshToken,
	})

	suite.helper.HasError(suite.T(), refreshResponse, "session_expired", "Session should expire after time-box duration")

	// Reset time-box to 0 (never expire)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"time_box_user_sessions": 0,
			},
		},
	}, nil)
	suite.Nil(resetResponse.Response.Error, "Config update should succeed")
}

// Test case: Inactivity timeout configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - getUser() method
// Configuration: pkg/config/session.go - InactivityTimeout field
func (suite *SessionConfigTestSuite) TestInactivityTimeout() {
	email := "inactivity-timeout-test@example.com"
	password := "SecurePassword2024!"

	// Disable email confirmation for immediate signin
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)

	// Sign up user
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signupResponse.Response.Error, "Signup should succeed")

	// Set short inactivity timeout (2 seconds for testing)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"inactivity_timeout": 2, // 2 seconds
			},
		},
	}, nil)
	suite.Nil(configResponse.Response.Error, "Config update should succeed")

	// User signs in
	signinResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signinResponse.Response.Error, "Signin should succeed")

	signinData := signinResponse.Response.Data.(map[string]interface{})
	sessionData := signinData["session"].(map[string]interface{})
	accessToken := sessionData["access_token"].(string)
	suite.NotEmpty(accessToken, "Should have access token")

	// Wait for inactivity timeout to expire
	time.Sleep(3 * time.Second)

	// Attempt to access protected endpoint after inactivity timeout
	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)

	suite.helper.HasError(suite.T(), userResponse, "session_expired", "Session should expire after inactivity timeout")

	// Reset inactivity timeout to 0 (no timeout)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"inactivity_timeout": 0,
			},
		},
	}, nil)
	suite.Nil(resetResponse.Response.Error, "Config update should succeed")
}

// Test case: Access token TTL configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signInWithPassword() method
// Configuration: pkg/config/session.go - AccessTokenTTL field
func (suite *SessionConfigTestSuite) TestAccessTokenTTL() {
	email := "access-token-ttl-test@example.com"
	password := "SecurePassword2024!"

	// Disable email confirmation for immediate signin
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)

	// Sign up user
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signupResponse.Response.Error, "Signup should succeed")

	// Set very short access token TTL (2 seconds)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"access_token_ttl": 2, // 2 seconds
			},
		},
	}, nil)
	suite.Nil(configResponse.Response.Error, "Config update should succeed")

	// User signs in
	signinResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", S{
		"email":    email,
		"password": password,
	})
	suite.Nil(signinResponse.Response.Error, "Signin should succeed")

	signinData := signinResponse.Response.Data.(map[string]interface{})
	sessionData := signinData["session"].(map[string]interface{})
	accessToken := sessionData["access_token"].(string)
	expiresIn := sessionData["expires_in"].(float64)
	suite.NotEmpty(accessToken, "Should have access token")
	suite.Equal(float64(2), expiresIn, "Access token should expire in 2 seconds")

	// Wait for access token to expire
	time.Sleep(3 * time.Second)

	// Attempt to use expired access token
	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(401, userResponse.ResponseRecorder.Code, "Expired access token should be rejected")

	// Reset to default access token TTL (1 hour)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"session_config": S{
				"access_token_ttl": 3600, // 1 hour in seconds
			},
		},
	}, nil)
	suite.Nil(resetResponse.Response.Error, "Config update should succeed")
}

func TestSessionConfigSuite(t *testing.T) {
	suite.Run(t, new(SessionConfigTestSuite))
}
