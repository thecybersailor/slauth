package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type RatelimitConfigTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *RatelimitConfigTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestDomain, suite.EmailProvider, suite.SMSProvider)
}

// Test case: Email sending rate limit configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - resend() method
// Configuration: pkg/config/ratelimit.go - EmailRateLimit field
func (suite *RatelimitConfigTestSuite) TestEmailRateLimit() {
	email := "email-ratelimit-test@example.com"
	password := "SecurePassword2024!"

	// Enable email confirmation to trigger OTP emails
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   true,
		},
	}, nil)

	// Sign up user to get initial OTP email
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	// Set strict email rate limit (1 email per minute)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"email_rate_limit": S{
					"max_requests":    1,
					"window_duration": 60000000000, // 1 minute in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// First resend should consume the rate limit quota
	resendResponse1 := suite.helper.MakePOSTRequest(suite.T(), "/auth/resend", S{
		"email": email,
		"type":  "signup",
	})
	suite.Equal(200, resendResponse1.ResponseRecorder.Code, "First resend should succeed")

	// Second immediate resend should be rate limited
	resendResponse2 := suite.helper.MakePOSTRequest(suite.T(), "/auth/resend", S{
		"email": email,
		"type":  "signup",
	})

	suite.helper.HasError(suite.T(), resendResponse2, "over_email_send_rate_limit", "Second resend should be rate limited")

	// Reset to default email rate limit (30 emails per hour)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"email_rate_limit": S{
					"max_requests":    30,
					"window_duration": 3600000000000, // 1 hour in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, resetResponse.ResponseRecorder.Code, "Config reset should succeed")
}

// Test case: Sign-up and sign-in rate limit configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signUp() and signInWithPassword() methods
// Configuration: pkg/config/ratelimit.go - SignUpSignInRateLimit field
func (suite *RatelimitConfigTestSuite) TestSignUpSignInRateLimit() {
	baseEmail := "signin-ratelimit-test"
	password := "SecurePassword2024!"

	// Disable email confirmation for immediate signin
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)

	// Set strict signin rate limit (2 requests per minute)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"sign_up_sign_in_rate_limit": S{
					"max_requests":    2,
					"window_duration": 60000000000, // 1 minute in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// First signup should succeed
	signup1Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    baseEmail + "1@example.com",
		"password": password,
	})
	suite.Equal(200, signup1Response.ResponseRecorder.Code, "First signup should succeed")

	// Second signup should succeed
	signup2Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    baseEmail + "2@example.com",
		"password": password,
	})
	suite.Equal(200, signup2Response.ResponseRecorder.Code, "Second signup should succeed")

	// Third signup should be rate limited
	signup3Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    baseEmail + "3@example.com",
		"password": password,
	})

	suite.helper.HasError(suite.T(), signup3Response, "over_request_rate_limit", "Third signup should be rate limited")

	// Reset to default signin rate limit (30 requests per 5 minutes)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"sign_up_sign_in_rate_limit": S{
					"max_requests":    30,
					"window_duration": 300000000000, // 5 minutes in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, resetResponse.ResponseRecorder.Code, "Config reset should succeed")
}

// Test case: Token refresh rate limit configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - refreshSession() method
// Configuration: pkg/config/ratelimit.go - TokenRefreshRateLimit field
func (suite *RatelimitConfigTestSuite) TestTokenRefreshRateLimit() {
	email := "token-refresh-ratelimit-test@example.com"
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
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	signupData := signupResponse.Response.Data.(map[string]interface{})
	sessionData := signupData["session"].(map[string]interface{})
	refreshToken := sessionData["refresh_token"].(string)
	suite.NotEmpty(refreshToken, "Should have refresh token")

	// Set strict token refresh rate limit (1 request per minute)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"token_refresh_rate_limit": S{
					"max_requests":    1,
					"window_duration": 60000000000, // 1 minute in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// First token refresh should succeed
	refresh1Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"refresh_token": refreshToken,
	})
	suite.Equal(200, refresh1Response.ResponseRecorder.Code, "First refresh should succeed")

	refresh1Data := refresh1Response.Response.Data.(map[string]interface{})
	refresh1Session := refresh1Data["session"].(map[string]interface{})
	newRefreshToken := refresh1Session["refresh_token"].(string)

	// Second immediate token refresh should be rate limited
	refresh2Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", S{
		"refresh_token": newRefreshToken,
	})

	suite.helper.HasError(suite.T(), refresh2Response, "over_request_rate_limit", "Second refresh should be rate limited")

	// Reset to default token refresh rate limit (30 requests per 5 minutes)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"token_refresh_rate_limit": S{
					"max_requests":    30,
					"window_duration": 300000000000, // 5 minutes in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, resetResponse.ResponseRecorder.Code, "Config reset should succeed")
}

// Test case: SMS rate limit configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - signUp() with phone method
// Configuration: pkg/config/ratelimit.go - SMSRateLimit field
func (suite *RatelimitConfigTestSuite) TestSMSRateLimit() {
	phone := "+1234567890"

	// Set strict SMS rate limit (1 SMS per minute)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"sms_rate_limit": S{
					"max_requests":    1,
					"window_duration": 60000000000, // 1 minute in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// First SMS OTP request should succeed
	otp1Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", S{
		"phone": phone,
	})
	suite.Equal(200, otp1Response.ResponseRecorder.Code, "First OTP request should succeed")

	// Second immediate SMS OTP request should be rate limited
	otp2Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", S{
		"phone": phone,
	})

	suite.helper.HasError(suite.T(), otp2Response, "over_sms_send_rate_limit", "Second OTP request should be rate limited")

	// Reset to default SMS rate limit (150 SMS per hour)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"sms_rate_limit": S{
					"max_requests":    150,
					"window_duration": 3600000000000, // 1 hour in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, resetResponse.ResponseRecorder.Code, "Config reset should succeed")
}

// Test case: Token verification rate limit configuration
// API Implementation: packages/slauth-ts/src/AuthApi.ts - verifyOtp() method
// Configuration: pkg/config/ratelimit.go - TokenVerificationRateLimit field
func (suite *RatelimitConfigTestSuite) TestTokenVerificationRateLimit() {
	email := "token-verification-ratelimit-test@example.com"
	password := "SecurePassword2024!"

	// Enable email confirmation to trigger OTP flow
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   true,
		},
	}, nil)

	// Sign up user to get OTP email
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	// Set strict token verification rate limit (2 attempts per minute)
	configResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"token_verification_rate_limit": S{
					"max_requests":    2,
					"window_duration": 60000000000, // 1 minute in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, configResponse.ResponseRecorder.Code, "Config update should succeed")

	// First verification attempt (with wrong code) should succeed
	verify1Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/verify", S{
		"email": email,
		"token": "000000",
		"type":  "signup",
	})
	suite.Equal(200, verify1Response.ResponseRecorder.Code, "First verification attempt should be processed")

	// Second verification attempt should succeed
	verify2Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/verify", S{
		"email": email,
		"token": "111111",
		"type":  "signup",
	})
	suite.Equal(200, verify2Response.ResponseRecorder.Code, "Second verification attempt should be processed")

	// Third verification attempt should be rate limited
	verify3Response := suite.helper.MakePOSTRequest(suite.T(), "/auth/verify", S{
		"email": email,
		"token": "222222",
		"type":  "signup",
	})

	suite.helper.HasError(suite.T(), verify3Response, "over_request_rate_limit", "Third verification attempt should be rate limited")

	// Reset to default token verification rate limit (30 attempts per 5 minutes)
	resetResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"ratelimit_config": S{
				"token_verification_rate_limit": S{
					"max_requests":    30,
					"window_duration": 300000000000, // 5 minutes in nanoseconds
				},
			},
		},
	}, nil)
	suite.Equal(200, resetResponse.ResponseRecorder.Code, "Config reset should succeed")
}

func TestRatelimitConfigSuite(t *testing.T) {
	suite.Run(t, new(RatelimitConfigTestSuite))
}
