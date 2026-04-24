package tests

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type SecureIdentityChangeCompatTestSuite struct {
	TestSuite
	helper           *TestHelper
	capturedOTPCodes []string
}

func (suite *SecureIdentityChangeCompatTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	cfg := suite.AuthService.GetConfig()
	trueVal := true
	cfg.ConfirmEmail = &trueVal
	suite.Require().NoError(suite.AuthService.SaveConfig(cfg))

	suite.AuthService.OTPUse(func(ctx services.OTPContext, next func() error) error {
		err := next()
		if err == nil && ctx.Response() != nil && ctx.Response().Code != "" {
			suite.capturedOTPCodes = append(suite.capturedOTPCodes, ctx.Response().Code)
		}
		return err
	})
}

func (suite *SecureIdentityChangeCompatTestSuite) clearCapturedOTPs() {
	suite.capturedOTPCodes = nil
}

func (suite *SecureIdentityChangeCompatTestSuite) lastCapturedOTP() string {
	if len(suite.capturedOTPCodes) == 0 {
		return ""
	}
	return suite.capturedOTPCodes[len(suite.capturedOTPCodes)-1]
}

func (suite *SecureIdentityChangeCompatTestSuite) confirmSignupEmail() string {
	mockEmailProvider := suite.helper.GetMockEmailProvider()
	lastEmail := mockEmailProvider.GetLastEmail()
	suite.Require().NotNil(lastEmail)

	body := lastEmail.Body
	tokenStart := strings.Index(body, "token=")
	suite.Require().NotEqual(-1, tokenStart)
	tokenStart += len("token=")

	tokenEnd := len(body)
	for i := tokenStart; i < len(body); i++ {
		char := body[i]
		if char == ' ' || char == '"' || char == '\'' || char == '>' || char == '&' {
			tokenEnd = i
			break
		}
	}

	token := body[tokenStart:tokenEnd]
	suite.Require().NotEmpty(token)

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+token)
	suite.Equal(200, confirmResponse.ResponseRecorder.Code)
	suite.Nil(confirmResponse.Error)

	return token
}

func (suite *SecureIdentityChangeCompatTestSuite) signUpAndSignIn(email, password string, extra S) string {
	signupRequestBody := S{
		"email":    email,
		"password": password,
	}
	for key, value := range extra {
		signupRequestBody[key] = value
	}

	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupRequestBody)
	suite.Equal(200, signupResponse.ResponseRecorder.Code)
	suite.Nil(signupResponse.Error)

	suite.confirmSignupEmail()

	loginRequestBody := S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	}
	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)
	suite.Equal(200, loginResponse.ResponseRecorder.Code)
	suite.Nil(loginResponse.Error)

	responseData := loginResponse.Data.(map[string]any)
	session := responseData["session"].(map[string]any)
	accessToken := session["access_token"].(string)
	suite.NotEmpty(accessToken)
	return accessToken
}

func (suite *SecureIdentityChangeCompatTestSuite) TestLegacyPasswordUpdateStillRequiresConfiguredAAL() {
	suite.clearCapturedOTPs()

	cfg := suite.AuthService.GetConfig()
	cfg.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL = types.AALLevel2

	email := fmt.Sprintf("compat-password-%d@example.com", time.Now().UnixNano())
	password := "CompatPassword123!"
	newPassword := "CompatPassword456!"
	accessToken := suite.signUpAndSignIn(email, password, nil)

	updatePasswordResponse := suite.helper.MakePUTRequest(
		suite.T(),
		"/auth/password",
		S{"password": newPassword},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)

	suite.helper.HasError(suite.T(), updatePasswordResponse, "insufficient_aal", "legacy password update should still require configured AAL")
}

func (suite *SecureIdentityChangeCompatTestSuite) TestLegacyEmailChangeReturnsSessionCodeAndVerifyStillWorks() {
	suite.clearCapturedOTPs()

	oldEmail := fmt.Sprintf("compat-email-old-%d@example.com", time.Now().UnixNano())
	newEmail := fmt.Sprintf("compat-email-new-%d@example.com", time.Now().UnixNano())
	password := "CompatPassword123!"
	accessToken := suite.signUpAndSignIn(oldEmail, password, nil)

	updateEmailResponse := suite.helper.MakePUTRequest(
		suite.T(),
		"/auth/email",
		S{"email": newEmail},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)

	suite.Equal(200, updateEmailResponse.ResponseRecorder.Code)
	suite.Nil(updateEmailResponse.Error)
	sessionCode := suite.helper.MustDataString(suite.T(), updateEmailResponse, "session_code")
	suite.NotEmpty(sessionCode)

	actualOTPCode := suite.lastCapturedOTP()
	suite.NotEmpty(actualOTPCode)

	verifyEmailResponse := suite.helper.MakePOSTRequestWithHeaders(
		suite.T(),
		"/auth/email/verify",
		S{
			"email":        newEmail,
			"token":        actualOTPCode,
			"session_code": sessionCode,
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)

	suite.Equal(200, verifyEmailResponse.ResponseRecorder.Code)
	suite.Nil(verifyEmailResponse.Error)

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code)
	userInfo := userResponse.Data.(map[string]any)["user"].(map[string]any)
	suite.Equal(newEmail, userInfo["email"])
}

func (suite *SecureIdentityChangeCompatTestSuite) TestLegacyPhoneChangeReturnsSessionCodeAndVerifyStillWorks() {
	suite.clearCapturedOTPs()

	email := fmt.Sprintf("compat-phone-%d@example.com", time.Now().UnixNano())
	oldPhone := fmt.Sprintf("+8613800%06d", time.Now().UnixNano()%1000000)
	newPhone := fmt.Sprintf("+8613900%06d", time.Now().UnixNano()%1000000)
	password := "CompatPassword123!"
	accessToken := suite.signUpAndSignIn(email, password, S{"phone": oldPhone})

	updatePhoneResponse := suite.helper.MakePUTRequest(
		suite.T(),
		"/auth/phone",
		S{"phone": newPhone},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)

	suite.Equal(200, updatePhoneResponse.ResponseRecorder.Code)
	suite.Nil(updatePhoneResponse.Error)
	sessionCode := suite.helper.MustDataString(suite.T(), updatePhoneResponse, "session_code")
	suite.NotEmpty(sessionCode)

	actualOTPCode := suite.lastCapturedOTP()
	suite.NotEmpty(actualOTPCode)

	verifyPhoneResponse := suite.helper.MakePOSTRequestWithHeaders(
		suite.T(),
		"/auth/phone/verify",
		S{
			"phone":        newPhone,
			"token":        actualOTPCode,
			"session_code": sessionCode,
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)

	suite.Equal(200, verifyPhoneResponse.ResponseRecorder.Code)
	suite.Nil(verifyPhoneResponse.Error)

	userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResponse.ResponseRecorder.Code)
	userInfo := userResponse.Data.(map[string]any)["user"].(map[string]any)
	suite.Equal(newPhone, userInfo["phone"])
}

func TestSecureIdentityChangeCompatTestSuite(t *testing.T) {
	suite.Run(t, new(SecureIdentityChangeCompatTestSuite))
}
