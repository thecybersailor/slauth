package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
)

type SecurityConfigTestSuite struct {
	TestSuite
	helper           *TestHelper
	capturedOTPCodes []string
}

func (suite *SecurityConfigTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(
		suite.DB,
		suite.Router,
		suite.TestInstance,
		suite.EmailProvider,
		suite.SMSProvider,
	)

	// Set up OTP capture middleware
	suite.AuthService.OTPUse(func(ctx services.OTPContext, next func() error) error {
		err := next()
		if err == nil && ctx.Response() != nil && ctx.Response().Code != "" {
			suite.capturedOTPCodes = append(suite.capturedOTPCodes, ctx.Response().Code)
			suite.T().Logf("Suite middleware captured OTP code: %s", ctx.Response().Code)
		}
		return err
	})
}

func (suite *SecurityConfigTestSuite) GetLastCapturedOTP() string {
	if len(suite.capturedOTPCodes) == 0 {
		return ""
	}
	return suite.capturedOTPCodes[len(suite.capturedOTPCodes)-1]
}

func (suite *SecurityConfigTestSuite) ClearCapturedOTPs() {
	suite.capturedOTPCodes = nil
}

func (suite *SecurityConfigTestSuite) SetupTest() {
	suite.ClearCapturedOTPs()
}

func TestSecurityConfigSuite(t *testing.T) {
	suite.Run(t, new(SecurityConfigTestSuite))
}

// Test scenario: Password Update Rate Limit Configuration
// This test validates that password update rate limiting works correctly
// Other security tests (AAL timeout, downgrade policy, session revocation, password strength)
// are already covered in 07-password-management_test.go:
// - TestAALTimeoutAutoDowngrade: AAL timeout and downgrade
// - TestUpdatePasswordUserAAL1/AAL2: AAL level requirements
// - TestPasswordUpdateRevokesOtherSessions: Session revocation
// - TestPasswordComplexityValidation: Password strength
func (suite *SecurityConfigTestSuite) Test_06_PasswordUpdateRateLimit() {
	// Get current config
	getConfigResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	suite.Equal(200, getConfigResponse.ResponseRecorder.Code)

	currentConfig := getConfigResponse.Data.(map[string]interface{})["config"].(map[string]interface{})
	originalSecurityConfig := currentConfig["security_config"].(map[string]interface{})

	// Test strict rate limit (2 password updates per hour)
	strictRateLimitConfig := map[string]interface{}{
		"aal_policy": originalSecurityConfig["aal_policy"],
		"password_update_config": map[string]interface{}{
			"update_required_aal":                         "aal1",
			"require_reauthentication_on_password_update": false,
			"revoke_other_sessions_on_password_update":    false,
			"rate_limit": map[string]interface{}{
				"max_requests":    2,
				"window_duration": 3600000000000, // 1 hour in nanoseconds
			},
		},
		"password_strength_config": originalSecurityConfig["password_strength_config"],
	}

	updateConfigRequest := S{
		"config": S{
			"site_url":                               currentConfig["site_url"],
			"auth_service_base_url":                  currentConfig["auth_service_base_url"],
			"redirect_urls":                          currentConfig["redirect_urls"],
			"allow_new_users":                        true,
			"confirm_email":                          false,
			"anonymous_sign_ins":                     currentConfig["anonymous_sign_ins"],
			"enable_captcha":                         currentConfig["enable_captcha"],
			"maximum_mfa_factors":                    currentConfig["maximum_mfa_factors"],
			"maximum_mfa_factor_validation_attempts": currentConfig["maximum_mfa_factor_validation_attempts"],
			"max_time_allowed_for_auth_request":      currentConfig["max_time_allowed_for_auth_request"],
			"session_config":                         currentConfig["session_config"],
			"ratelimit_config":                       currentConfig["ratelimit_config"],
			"security_config":                        strictRateLimitConfig,
		},
	}

	updateConfigResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", updateConfigRequest, nil)
	suite.Equal(200, updateConfigResponse.ResponseRecorder.Code, "Strict rate limit config update should succeed")

	// Test user signup and password updates
	email := "password-ratelimit-test@example.com"
	password := "InitialPassword123!"

	signupRequest := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequest)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	// Login to get access token
	loginRequest := S{
		"email":    email,
		"password": password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=password", loginRequest)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]interface{})
	session := responseData["session"].(map[string]interface{})
	accessToken := session["access_token"].(string)

	passwordHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	// First password update should succeed
	updatePasswordRequest1 := S{
		"password": "NewPassword456!",
	}
	passwordResponse1 := suite.helper.MakePUTRequest(suite.T(), "/auth/password", updatePasswordRequest1, passwordHeaders)
	suite.Equal(200, passwordResponse1.ResponseRecorder.Code, "First password update should succeed")

	// Second password update should succeed
	updatePasswordRequest2 := S{
		"password": "NewPassword789!",
	}
	passwordResponse2 := suite.helper.MakePUTRequest(suite.T(), "/auth/password", updatePasswordRequest2, passwordHeaders)
	suite.Equal(200, passwordResponse2.ResponseRecorder.Code, "Second password update should succeed")

	// Third password update should be rate limited
	updatePasswordRequest3 := S{
		"password": "NewPassword101!",
	}
	passwordResponse3 := suite.helper.MakePUTRequest(suite.T(), "/auth/password", updatePasswordRequest3, passwordHeaders)
	suite.helper.HasError(suite.T(), passwordResponse3, "over_request_rate_limit", "Third password update should be rate limited")

	suite.T().Logf("Password update rate limit test completed successfully")
}
