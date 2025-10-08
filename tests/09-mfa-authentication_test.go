package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type MFAAuthenticationTestSuite struct {
	EmailPhoneManagementTestSuite
}

func TestMFAAuthenticationTestSuite(t *testing.T) {
	suite.Run(t, new(MFAAuthenticationTestSuite))
}

func (suite *MFAAuthenticationTestSuite) SetupTest() {

	suite.ClearCapturedOTPs()
}

func (suite *MFAAuthenticationTestSuite) loginAndUpgradeToAAL2(email, password string) string {
	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed")

	if loginResponse.Response.Data == nil {
		suite.T().Fatalf("Login response data is nil")
	}

	responseData, ok := loginResponse.Response.Data.(map[string]any)
	if !ok {
		suite.T().Fatalf("Login response data is not a map")
	}

	session, ok := responseData["session"].(map[string]any)
	if !ok {
		suite.T().Fatalf("Session data is not a map")
	}

	accessToken, ok := session["access_token"].(string)
	if !ok {
		suite.T().Fatalf("Access token is not a string")
	}

	otpRequestBody := S{
		"email": email,
	}
	otpResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", otpRequestBody)
	suite.Equal(200, otpResponse.ResponseRecorder.Code, "OTP sending should succeed")

	actualOTPCode := suite.GetLastCapturedOTP()
	verifyRequestBody := S{
		"email": email,
		"token": actualOTPCode,
	}

	verifyHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/verify", verifyRequestBody, verifyHeaders)
	suite.Equal(200, verifyResponse.ResponseRecorder.Code, "OTP verification should succeed")

	return accessToken
}

func (suite *MFAAuthenticationTestSuite) TestTOTPFactorEnrollment() {

	email := "totp-enrollment@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	// Confirm email
	confirmationToken := suite.GetConfirmationTokenFromEmail()
	suite.Require().NotEmpty(confirmationToken, "Confirmation token should be extracted from email")

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+confirmationToken)
	suite.Require().Nil(confirmResponse.Response.Error, "Email confirmation should succeed")

	accessToken := suite.loginAndUpgradeToAAL2(email, password)

	enrollRequestBody := S{
		"factorType":   "totp",
		"friendlyName": "My TOTP Device",
	}

	enrollHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	enrollResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/factors/enroll", enrollRequestBody, enrollHeaders)

	suite.Equal(200, enrollResponse.ResponseRecorder.Code, "TOTP enrollment should succeed")
	suite.Nil(enrollResponse.Response.Error, "TOTP enrollment should not have error")
	suite.NotNil(enrollResponse.Response.Data, "TOTP enrollment should return data")

	enrollData, ok := enrollResponse.Response.Data.(map[string]any)
	suite.True(ok, "Enrollment data should be a map")

	suite.Equal("totp", enrollData["type"], "Factor type should be totp")
	suite.Equal("My TOTP Device", enrollData["friendly_name"], "Friendly name should match")
	suite.NotEmpty(enrollData["id"], "Factor ID should not be empty")

	totpData, ok := enrollData["totp"].(map[string]any)
	suite.True(ok, "TOTP data should be present")
	suite.NotEmpty(totpData["secret"], "TOTP secret should not be empty")
	suite.NotEmpty(totpData["qr_code"], "QR code should not be empty")
	suite.NotEmpty(totpData["uri"], "TOTP URI should not be empty")

	factorID := enrollData["id"].(string)

	verifyRequestBody := S{
		"factorId":    factorID,
		"challengeId": factorID,
		"code":        "123456",
	}

	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/factors/verify", verifyRequestBody, enrollHeaders)

	suite.Equal(200, verifyResponse.ResponseRecorder.Code, "TOTP verification should succeed")
	suite.Nil(verifyResponse.Response.Error, "TOTP verification should not have error")

	factorsResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/factors", accessToken)
	suite.Equal(200, factorsResponse.ResponseRecorder.Code, "Get factors should succeed")
	suite.NotNil(factorsResponse.Response.Data, "Factors data should not be nil")

	factorsData, ok := factorsResponse.Response.Data.(map[string]any)
	suite.True(ok, "Factors data should be a map")

	allFactors, ok := factorsData["all"].([]any)
	suite.True(ok, "All factors should be an array")
	suite.Len(allFactors, 1, "Should have one factor")

	factor := allFactors[0].(map[string]any)
	suite.Equal(factorID, factor["id"], "Factor ID should match")
	suite.Equal("totp", factor["type"], "Factor type should be totp")
	suite.Equal("verified", factor["status"], "Factor status should be verified")
}

func (suite *MFAAuthenticationTestSuite) TestTOTPAuthentication() {

}

func (suite *MFAAuthenticationTestSuite) TestTOTPFactorUnenrollment() {

}

func (suite *MFAAuthenticationTestSuite) TestTOTPCodeValidation() {

}

func (suite *MFAAuthenticationTestSuite) TestTOTPWithMultipleFactors() {

}
