package tests

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
)

type OTPVerificationTestSuite struct {
	TestSuite
	helper           *TestHelper
	capturedOTPCodes []string
}

func (suite *OTPVerificationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestDomain, suite.EmailProvider, suite.SMSProvider)

	suite.AuthService.OTPUse(func(ctx services.OTPContext, next func() error) error {
		err := next()
		if err == nil && ctx.Response() != nil && ctx.Response().Code != "" {
			suite.capturedOTPCodes = append(suite.capturedOTPCodes, ctx.Response().Code)
			suite.T().Logf("Suite middleware captured OTP code: %s", ctx.Response().Code)
		}
		return err
	})
}

func (suite *OTPVerificationTestSuite) GetLastCapturedOTP() string {
	if len(suite.capturedOTPCodes) == 0 {
		return ""
	}
	return suite.capturedOTPCodes[len(suite.capturedOTPCodes)-1]
}

func (suite *OTPVerificationTestSuite) ClearCapturedOTPs() {
	suite.capturedOTPCodes = nil
}

func (suite *OTPVerificationTestSuite) TestSendEmailOTP() {
	email := "test-otp@example.com"

	requestBody := S{
		"email": email,
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Send email OTP should succeed")

	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(lastEmail, "Should have sent an email")
	suite.Equal(email, lastEmail.To, "Email should be sent to correct recipient")
	suite.Equal("Your verification code", lastEmail.Subject, "Email subject should be correct")
	suite.Contains(lastEmail.Body, "Your verification code is:", "Email body should contain verification code")
	suite.T().Logf("Email body: %s", lastEmail.Body)

	suite.Regexp(`Your verification code is: \d{6}`, lastEmail.Body, "Email should contain 6-digit verification code")
}

func (suite *OTPVerificationTestSuite) TestSendSMSOTP() {
	phone := "+1234567890"

	requestBody := S{
		"phone": phone,
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/sms-otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Send SMS OTP should succeed")

	mockSMSProvider := suite.helper.GetMockSMSProvider()
	lastSMS := mockSMSProvider.GetLastSMS()
	suite.NotNil(lastSMS, "Should have sent an SMS")
	suite.Equal(phone, lastSMS.To, "SMS should be sent to correct recipient")
	suite.Contains(lastSMS.Body, "Your verification code is:", "SMS body should contain verification code")
	suite.T().Logf("SMS body: %s", lastSMS.Body)

	suite.Regexp(`Your verification code is: \d{6}`, lastSMS.Body, "SMS should contain 6-digit verification code")
}

func (suite *OTPVerificationTestSuite) TestSendOTPWithInvalidEmail() {

	requestBody := S{
		"email": "",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Should return 200 status code")
	suite.NotNil(response.Response.Error, "Should have validation error for empty email")

	requestBody = S{
		"email": "invalid-email",
	}

	response = suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Should return 200 status code")
	suite.NotNil(response.Response.Error, "Should have validation error for invalid email format")
}

func (suite *OTPVerificationTestSuite) TestSendOTPWithInvalidPhone() {

	requestBody := S{
		"phone": "",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/sms-otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Should return 200 status code")
	suite.NotNil(response.Response.Error, "Should have validation error for empty phone")
}

func (suite *OTPVerificationTestSuite) TestSendOTPWithBothEmailAndPhone() {

	suite.ClearCapturedOTPs()

	requestBody := S{
		"email": "test-both@example.com",
		"phone": "+1234567890",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Send OTP to both email and phone should succeed")

	actualOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(actualOTPCode, "Should have captured OTP code")

	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(lastEmail, "Should have sent an email")
	suite.Equal("test-both@example.com", lastEmail.To, "Email should be sent to correct recipient")

	mockSMSProvider := suite.helper.GetMockSMSProvider()
	lastSMS := mockSMSProvider.GetLastSMS()
	suite.NotNil(lastSMS, "Should have sent an SMS")
	suite.Equal("+1234567890", lastSMS.To, "SMS should be sent to correct recipient")

	suite.True(strings.Contains(lastEmail.Body, actualOTPCode), "Email should contain actual verification code")
	suite.True(strings.Contains(lastSMS.Body, actualOTPCode), "SMS should contain actual verification code")

	suite.T().Logf("Email body: %s", lastEmail.Body)
	suite.T().Logf("SMS body: %s", lastSMS.Body)
	suite.T().Logf("Extracted verification code: %s", actualOTPCode)
}

func (suite *OTPVerificationTestSuite) TestVerifyOTP() {

	suite.ClearCapturedOTPs()

	email := "verify-test@example.com"
	sendRequestBody := S{
		"email": email,
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", sendRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Send OTP should succeed")

	actualOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(actualOTPCode, "Should have captured OTP code")

	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(lastEmail, "Should have sent an email")

	suite.T().Logf("Email body: %s", lastEmail.Body)
	suite.T().Logf("Captured OTP code: %s", actualOTPCode)

	suite.True(strings.Contains(lastEmail.Body, actualOTPCode), "Email should contain actual verification code")

	suite.T().Logf("About to verify with OTP code: '%s'", actualOTPCode)
	verifyRequestBody := S{
		"email": email,
		"token": actualOTPCode,
		"type":  "signup",
	}

	suite.T().Logf("Verify request body: %+v", verifyRequestBody)
	response = suite.helper.MakePOSTRequest(suite.T(), "/auth/verify", verifyRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Verify OTP should succeed")

	suite.Nil(response.Response.Error, "Should not have error for valid verification")
	if response.Response.Data != nil {
		responseData := response.Response.Data.(map[string]any)
		suite.Equal(true, responseData["success"], "Verification should be successful")
	}
}

func (suite *OTPVerificationTestSuite) TestVerifyOTPWithInvalidCode() {
	email := "invalid-code-test@example.com"

	verifyRequestBody := S{
		"email": email,
		"token": "123456",
		"type":  "signup",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/verify", verifyRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Should return 200 status code")

	suite.NotNil(response.Response.Error, "Should have error for invalid verification code")
	suite.Equal("auth.validation_failed", response.Response.Error.Key, "Should return auth.validation_failed error")
}

func (suite *OTPVerificationTestSuite) TestVerifyOTPWithExpiredCode() {

	suite.T().Skip("Expired code test not implemented yet - requires code storage mechanism")
}

func (suite *OTPVerificationTestSuite) TestResendOTP() {
	email := "resend-test@example.com"

	suite.ClearCapturedOTPs()

	requestBody := S{
		"email": email,
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "First OTP send should succeed")

	firstOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(firstOTPCode, "Should have captured first OTP code")

	mockEmailProvider := suite.helper.GetMockEmailProvider()
	firstEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(firstEmail, "Should have sent first email")
	suite.T().Logf("First email body: %s", firstEmail.Body)

	suite.True(strings.Contains(firstEmail.Body, firstOTPCode), "First email should contain actual verification code")

	resendRequestBody := S{
		"type":  "signup",
		"email": email,
	}

	response = suite.helper.MakePOSTRequest(suite.T(), "/auth/resend", resendRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Resend OTP should succeed")

	secondOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(secondOTPCode, "Should have captured second OTP code")

	secondEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(secondEmail, "Should have sent second email")
	suite.T().Logf("Second email body: %s", secondEmail.Body)

	suite.True(strings.Contains(secondEmail.Body, secondOTPCode), "Second email should contain actual verification code")

	suite.NotEqual(firstOTPCode, secondOTPCode, "Resent email should contain different verification code")
	suite.Equal(email, secondEmail.To, "Resent email should go to correct recipient")
}

func (suite *OTPVerificationTestSuite) TestResendSMSOTP() {
	phone := "+1234567890"

	suite.ClearCapturedOTPs()

	requestBody := S{
		"phone": phone,
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/sms-otp", requestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "First SMS OTP send should succeed")

	firstOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(firstOTPCode, "Should have captured first SMS OTP code")

	mockSMSProvider := suite.helper.GetMockSMSProvider()
	firstSMS := mockSMSProvider.GetLastSMS()
	suite.NotNil(firstSMS, "Should have sent first SMS")
	suite.T().Logf("First SMS body: %s", firstSMS.Body)

	suite.True(strings.Contains(firstSMS.Body, firstOTPCode), "First SMS should contain actual verification code")

	resendRequestBody := S{
		"type":  "sms",
		"phone": phone,
	}

	response = suite.helper.MakePOSTRequest(suite.T(), "/auth/resend", resendRequestBody)
	suite.Equal(200, response.ResponseRecorder.Code, "Resend SMS OTP should succeed")

	secondOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(secondOTPCode, "Should have captured second SMS OTP code")

	secondSMS := mockSMSProvider.GetLastSMS()
	suite.NotNil(secondSMS, "Should have sent second SMS")
	suite.T().Logf("Second SMS body: %s", secondSMS.Body)

	suite.True(strings.Contains(secondSMS.Body, secondOTPCode), "Second SMS should contain actual verification code")

	suite.NotEqual(firstOTPCode, secondOTPCode, "Resent SMS should contain different verification code")
	suite.Equal(phone, secondSMS.To, "Resent SMS should go to correct recipient")
}

func TestOTPVerificationTestSuite(t *testing.T) {
	suite.Run(t, new(OTPVerificationTestSuite))
}
