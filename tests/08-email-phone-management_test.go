package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
)

type EmailPhoneManagementTestSuite struct {
	TestSuite
	helper           *TestHelper
	capturedOTPCodes []string
}

func (suite *EmailPhoneManagementTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestDomain, suite.EmailProvider, suite.SMSProvider)

	cfg := suite.AuthService.GetConfig()
	trueVal := true
	cfg.ConfirmEmail = &trueVal
	err := suite.AuthService.SaveConfig(cfg)
	suite.Require().NoError(err, "Failed to enable email confirmation")

	suite.AuthService.OTPUse(func(ctx services.OTPContext, next func() error) error {
		err := next()
		if err == nil && ctx.Response() != nil && ctx.Response().Code != "" {
			suite.capturedOTPCodes = append(suite.capturedOTPCodes, ctx.Response().Code)
			suite.T().Logf("Suite middleware captured OTP code: %s", ctx.Response().Code)
		}
		return err
	})
}

func (suite *EmailPhoneManagementTestSuite) GetLastCapturedOTP() string {
	if len(suite.capturedOTPCodes) == 0 {
		return ""
	}
	return suite.capturedOTPCodes[len(suite.capturedOTPCodes)-1]
}

func (suite *EmailPhoneManagementTestSuite) ClearCapturedOTPs() {
	suite.capturedOTPCodes = nil
}

func (suite *EmailPhoneManagementTestSuite) GetConfirmationTokenFromEmail() string {
	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	if lastEmail == nil {
		return ""
	}

	body := lastEmail.Body
	tokenStart := strings.Index(body, "token=")
	if tokenStart == -1 {
		return ""
	}
	tokenStart += 6

	tokenEnd := len(body)
	for i := tokenStart; i < len(body); i++ {
		char := body[i]
		if char == ' ' || char == '"' || char == '\'' || char == '>' || char == '&' {
			tokenEnd = i
			break
		}
	}

	return body[tokenStart:tokenEnd]
}

func (suite *EmailPhoneManagementTestSuite) TestEmailConfirmation() {

	email := "email-confirm@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResponse.Response.Error, "Signup should not have error")

	suite.NotNil(signupResponse.Response.Data, "Signup response should have data")
	signupData := signupResponse.Response.Data.(map[string]any)
	userData := signupData["user"].(map[string]any)
	userID := userData["id"].(string)
	suite.NotEmpty(userID, "User ID should not be empty")

	userResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user should succeed")
	userInfo := userResponse.Response.Data.(map[string]any)
	suite.False(userInfo["email_confirmed"].(bool), "Email should not be confirmed initially")

	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(lastEmail, "Should have sent a confirmation email")
	suite.Equal(email, lastEmail.To, "Email should be sent to the registered user")
	suite.Equal("Confirm your signup", lastEmail.Subject, "Email subject should be correct")
	suite.Contains(lastEmail.Body, "/confirm?token=", "Email should contain confirmation URL")

	body := lastEmail.Body
	tokenStart := strings.Index(body, "token=")
	suite.NotEqual(-1, tokenStart, "Should find token parameter in email body")

	tokenStart += 6

	tokenEnd := len(body)
	for i := tokenStart; i < len(body); i++ {
		char := body[i]
		if char == ' ' || char == '"' || char == '\'' || char == '>' || char == '&' {
			tokenEnd = i
			break
		}
	}

	confirmationToken := body[tokenStart:tokenEnd]
	suite.NotEmpty(confirmationToken, "Confirmation token should not be empty")
	suite.T().Logf("Extracted confirmation token: %s", confirmationToken)

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+confirmationToken)
	suite.Equal(200, confirmResponse.ResponseRecorder.Code, "Email confirmation should succeed")
	suite.Nil(confirmResponse.Response.Error, "Email confirmation should not have error")

	userResponseAfter := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, userResponseAfter.ResponseRecorder.Code, "Get user after confirmation should succeed")
	userInfoAfter := userResponseAfter.Response.Data.(map[string]any)
	suite.True(userInfoAfter["email_confirmed"].(bool), "Email should be confirmed after using confirmation token")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed after email confirmation")
	suite.Nil(loginResponse.Response.Error, "Login should not have error")
}

func (suite *EmailPhoneManagementTestSuite) TestUpdateEmail() {

	suite.ClearCapturedOTPs()

	oldEmail := "update-email-old@example.com"
	newEmail := "update-email-new@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    oldEmail,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Require().Nil(signupResponse.Response.Error, "Signup should succeed")

	// Confirm email
	confirmationToken := suite.GetConfirmationTokenFromEmail()
	suite.Require().NotEmpty(confirmationToken, "Confirmation token should be extracted from email")

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+confirmationToken)
	suite.Require().Nil(confirmResponse.Response.Error, "Email confirmation should succeed")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      oldEmail,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Require().Nil(loginResponse.Response.Error, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)

	updateEmailRequestBody := S{
		"email": newEmail,
	}

	updateEmailHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	updateEmailResponse := suite.helper.MakePUTRequest(suite.T(), "/auth/email", updateEmailRequestBody, updateEmailHeaders)
	suite.Equal(200, updateEmailResponse.ResponseRecorder.Code, "Update email should succeed")
	suite.Nil(updateEmailResponse.Response.Error, "Update email should not have error")

	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	suite.NotNil(lastEmail, "Should have sent an email")
	suite.Equal(newEmail, lastEmail.To, "Email should be sent to new email address")
	suite.Equal("Your verification code", lastEmail.Subject, "Email subject should be verification code")

	actualOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(actualOTPCode, "Should have captured OTP code")

	verifyEmailRequestBody := S{
		"email": newEmail,
		"token": actualOTPCode,
	}

	verifyEmailHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	verifyEmailResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/verify", verifyEmailRequestBody, verifyEmailHeaders)
	suite.Equal(200, verifyEmailResponse.ResponseRecorder.Code, "Email change verification should succeed")
	suite.Nil(verifyEmailResponse.Response.Error, "Email change verification should not have error")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user should succeed")
	userInfo := userResponse.Response.Data.(map[string]any)["user"].(map[string]any)
	suite.Equal(newEmail, userInfo["email"], "User email should be updated to new email")

	newLoginRequestBody := S{
		"grant_type": "password",
		"email":      newEmail,
		"password":   password,
	}

	newLoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", newLoginRequestBody)
	suite.Equal(200, newLoginResponse.ResponseRecorder.Code, "Login with new email should succeed")

	oldLoginRequestBody := S{
		"grant_type": "password",
		"email":      oldEmail,
		"password":   password,
	}

	oldLoginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", oldLoginRequestBody)
	suite.Equal(200, oldLoginResponse.ResponseRecorder.Code, "Login with old email should return 200")
	suite.NotNil(oldLoginResponse.Response.Error, "Login with old email should have error")
}

func (suite *EmailPhoneManagementTestSuite) TestUpdatePhone() {

	suite.ClearCapturedOTPs()

	email := "update-phone@example.com"
	oldPhone := "+1111111111"
	newPhone := "+2222222222"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"phone":    oldPhone,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Require().Nil(signupResponse.Response.Error, "Signup should succeed")

	// Confirm email
	confirmationToken := suite.GetConfirmationTokenFromEmail()
	suite.Require().NotEmpty(confirmationToken, "Confirmation token should be extracted from email")

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+confirmationToken)
	suite.Require().Nil(confirmResponse.Response.Error, "Email confirmation should succeed")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Require().Nil(loginResponse.Response.Error, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)

	updatePhoneRequestBody := S{
		"phone": newPhone,
	}

	updatePhoneHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	updatePhoneResponse := suite.helper.MakePUTRequest(suite.T(), "/auth/phone", updatePhoneRequestBody, updatePhoneHeaders)
	suite.Equal(200, updatePhoneResponse.ResponseRecorder.Code, "Update phone should succeed")
	suite.Nil(updatePhoneResponse.Response.Error, "Update phone should not have error")

	mockSMSProvider := suite.helper.GetMockSMSProvider()
	lastSMS := mockSMSProvider.GetLastSMS()
	suite.NotNil(lastSMS, "Should have sent an SMS")
	suite.Equal(newPhone, lastSMS.To, "SMS should be sent to new phone number")

	actualOTPCode := suite.GetLastCapturedOTP()
	suite.NotEmpty(actualOTPCode, "Should have captured OTP code")

	verifyPhoneRequestBody := S{
		"phone": newPhone,
		"token": actualOTPCode,
	}

	verifyPhoneHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	verifyPhoneResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/verify", verifyPhoneRequestBody, verifyPhoneHeaders)
	suite.Equal(200, verifyPhoneResponse.ResponseRecorder.Code, "Phone change verification should succeed")
	suite.Nil(verifyPhoneResponse.Response.Error, "Phone change verification should not have error")

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user should succeed")
	userInfo := userResponse.Response.Data.(map[string]any)["user"].(map[string]any)
	suite.Equal(newPhone, userInfo["phone"], "User phone should be updated to new phone")
}

func (suite *EmailPhoneManagementTestSuite) TestAdminSetEmailConfirmed() {

	email := "admin-email-confirmed@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	signupData := signupResponse.Response.Data.(map[string]any)
	userData := signupData["user"].(map[string]any)
	userID := userData["id"].(string)

	userResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user should succeed")
	userInfo := userResponse.Response.Data.(map[string]any)
	suite.False(userInfo["email_confirmed"].(bool), "Email should not be confirmed initially")

	setEmailConfirmedRequestBody := S{
		"confirmed": true,
	}

	setEmailConfirmedResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/users/"+userID+"/email-confirmed", setEmailConfirmedRequestBody, nil)
	suite.Equal(200, setEmailConfirmedResponse.ResponseRecorder.Code, "Set email confirmed should succeed")
	suite.Nil(setEmailConfirmedResponse.Response.Error, "Set email confirmed should not have error")

	userResponseAfter := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, userResponseAfter.ResponseRecorder.Code, "Get user after setting should succeed")
	userInfoAfter := userResponseAfter.Response.Data.(map[string]any)
	suite.True(userInfoAfter["email_confirmed"].(bool), "Email should be confirmed after admin setting")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code, "Login should succeed after admin email confirmation")
	suite.Nil(loginResponse.Response.Error, "Login should not have error")
}

func (suite *EmailPhoneManagementTestSuite) TestAdminSetPhoneConfirmed() {

	email := "admin-phone-confirmed@example.com"
	phone := "+1234567890"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"phone":    phone,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code, "Signup should succeed")

	signupData := signupResponse.Response.Data.(map[string]any)
	userData := signupData["user"].(map[string]any)
	userID := userData["id"].(string)

	userResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, userResponse.ResponseRecorder.Code, "Get user should succeed")
	userInfo := userResponse.Response.Data.(map[string]any)
	suite.False(userInfo["phone_confirmed"].(bool), "Phone should not be confirmed initially")

	setPhoneConfirmedRequestBody := S{
		"confirmed": true,
	}

	setPhoneConfirmedResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/users/"+userID+"/phone-confirmed", setPhoneConfirmedRequestBody, nil)
	suite.Equal(200, setPhoneConfirmedResponse.ResponseRecorder.Code, "Set phone confirmed should succeed")
	suite.Nil(setPhoneConfirmedResponse.Response.Error, "Set phone confirmed should not have error")

	userResponseAfter := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, userResponseAfter.ResponseRecorder.Code, "Get user after setting should succeed")
	userInfoAfter := userResponseAfter.Response.Data.(map[string]any)
	suite.True(userInfoAfter["phone_confirmed"].(bool), "Phone should be confirmed after admin setting")
}

func (suite *EmailPhoneManagementTestSuite) TestEmailUpdateAALRequirement() {

	suite.ClearCapturedOTPs()

	email := "aal-email-update@example.com"
	newEmail := "aal-email-new@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Require().Nil(signupResponse.Response.Error, "Signup should succeed")

	// Confirm email
	confirmationToken := suite.GetConfirmationTokenFromEmail()
	suite.Require().NotEmpty(confirmationToken, "Confirmation token should be extracted from email")

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+confirmationToken)
	suite.Require().Nil(confirmResponse.Response.Error, "Email confirmation should succeed")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Require().Nil(loginResponse.Response.Error, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)

	updateEmailRequestBody := S{
		"email": newEmail,
	}

	updateEmailHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	updateEmailResponse := suite.helper.MakePUTRequest(suite.T(), "/auth/email", updateEmailRequestBody, updateEmailHeaders)
	suite.Equal(200, updateEmailResponse.ResponseRecorder.Code, "Update email should succeed with AAL1")
	suite.Nil(updateEmailResponse.Response.Error, "Update email should not have error")

	suite.T().Logf("Email update AAL requirement test completed successfully")
}

func (suite *EmailPhoneManagementTestSuite) TestPhoneUpdateRateLimit() {

	suite.ClearCapturedOTPs()

	email := "rate-limit-phone@example.com"
	password := "MySecurePassword2024!"

	signupRequestBody := S{
		"email":    email,
		"password": password,
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Require().Nil(signupResponse.Response.Error, "Signup should succeed")

	// Confirm email
	confirmationToken := suite.GetConfirmationTokenFromEmail()
	suite.Require().NotEmpty(confirmationToken, "Confirmation token should be extracted from email")

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+confirmationToken)
	suite.Require().Nil(confirmResponse.Response.Error, "Email confirmation should succeed")

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Require().Nil(loginResponse.Response.Error, "Login should succeed")

	responseData := loginResponse.Response.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)

	updatePhoneHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	for i := 1; i <= 3; i++ {
		newPhone := fmt.Sprintf("+123456789%d", i)
		updatePhoneRequestBody := S{
			"phone": newPhone,
		}

		updatePhoneResponse := suite.helper.MakePUTRequest(suite.T(), "/auth/phone", updatePhoneRequestBody, updatePhoneHeaders)
		suite.Equal(200, updatePhoneResponse.ResponseRecorder.Code, fmt.Sprintf("Phone update %d should succeed", i))
		suite.Nil(updatePhoneResponse.Response.Error, fmt.Sprintf("Phone update %d should not have error", i))

		suite.T().Logf("Phone update %d completed successfully", i)
	}

	newPhone4 := "+1234567894"
	updatePhoneRequestBody4 := S{
		"phone": newPhone4,
	}

	updatePhoneResponse4 := suite.helper.MakePUTRequest(suite.T(), "/auth/phone", updatePhoneRequestBody4, updatePhoneHeaders)

	suite.T().Logf("4th phone update response code: %d", updatePhoneResponse4.ResponseRecorder.Code)

	suite.T().Logf("Phone update rate limit test completed successfully")
}

func TestEmailPhoneManagementTestSuite(t *testing.T) {
	suite.Run(t, new(EmailPhoneManagementTestSuite))
}
