package tests

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/config"
)

type SecurePhoneChangeTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SecurePhoneChangeTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

func (suite *SecurePhoneChangeTestSuite) extractLastEmailCode() string {
	re := regexp.MustCompile(`\b\d{6}\b`)
	if lastEmail := suite.helper.GetMockEmailProvider().GetLastEmail(); lastEmail != nil {
		return re.FindString(lastEmail.Body)
	}
	return ""
}

func (suite *SecurePhoneChangeTestSuite) extractLastSMSCode() string {
	re := regexp.MustCompile(`\b\d{6}\b`)
	if lastSMS := suite.helper.GetMockSMSProvider().GetLastSMS(); lastSMS != nil {
		return re.FindString(lastSMS.Body)
	}
	return ""
}

func (suite *SecurePhoneChangeTestSuite) signUpConfirmAndLogin(email, phone, password string) string {
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"phone":    phone,
		"password": password,
	})
	suite.Equal(200, signupResponse.ResponseRecorder.Code)
	suite.Nil(signupResponse.Error)

	lastEmail := suite.helper.GetMockEmailProvider().GetLastEmail()
	suite.Require().NotNil(lastEmail)
	body := lastEmail.Body
	tokenStart := len("token=")
	token := ""
	for i := 0; i < len(body)-tokenStart; i++ {
		if body[i:i+tokenStart] == "token=" {
			start := i + tokenStart
			end := start
			for end < len(body) && body[end] != ' ' && body[end] != '"' && body[end] != '\'' && body[end] != '>' && body[end] != '&' {
				end++
			}
			token = body[start:end]
			break
		}
	}
	suite.Require().NotEmpty(token)

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+token)
	suite.Equal(200, confirmResponse.ResponseRecorder.Code)
	suite.Nil(confirmResponse.Error)

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      email,
		"password":   password,
	})
	suite.Equal(200, loginResponse.ResponseRecorder.Code)
	suite.Nil(loginResponse.Error)

	session := loginResponse.Data.(map[string]any)["session"].(map[string]any)
	return session["access_token"].(string)
}

func (suite *SecurePhoneChangeTestSuite) upgradeToAAL2(accessToken string) {
	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate", S{}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)
	suite.Nil(startResponse.Error)

	code := suite.extractLastEmailCode()
	sessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	suite.NotEmpty(code)
	suite.NotEmpty(sessionCode)

	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate/verify", S{
		"token":        code,
		"session_code": sessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, verifyResponse.ResponseRecorder.Code)
	suite.Nil(verifyResponse.Error)
}

func (suite *SecurePhoneChangeTestSuite) setRequireCurrentPhoneConfirmation(enabled bool) {
	update := config.NewDefaultAuthServiceConfig()
	update.SecurityConfig = &config.SecurityConfig{
		PhoneChangeConfig: config.IdentityChangeConfig{
			RequiredAAL:                     update.SecurityConfig.PhoneChangeConfig.RequiredAAL,
			RequireCurrentValueConfirmation: enabled,
			RateLimit:                       update.SecurityConfig.PhoneChangeConfig.RateLimit,
		},
	}
	suite.Require().NoError(suite.AuthService.SaveConfig(update))
}

func (suite *SecurePhoneChangeTestSuite) TestSecurePhoneChangeRequiresAAL2() {
	email := fmt.Sprintf("secure-phone-aal-%d@example.com", time.Now().UnixNano())
	accessToken := suite.signUpConfirmAndLogin(email, "+11111111111", "SecurePhone123!")

	response := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change", S{
		"phone": "+12222222222",
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})

	suite.NotNil(response.Error)
	suite.Contains(response.Error.Key, "insufficient_aal")
}

func (suite *SecurePhoneChangeTestSuite) TestSecurePhoneChangeStartsFlowAndVerifiesNewPhone() {
	suite.setRequireCurrentPhoneConfirmation(false)

	email := fmt.Sprintf("secure-phone-start-%d@example.com", time.Now().UnixNano())
	accessToken := suite.signUpConfirmAndLogin(email, "+13333333333", "SecurePhone123!")
	suite.upgradeToAAL2(accessToken)

	newPhone := "+14444444444"
	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change", S{
		"phone": newPhone,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)
	suite.Nil(startResponse.Error)

	flowID := suite.helper.MustDataString(suite.T(), startResponse, "flow_id")
	sessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	code := suite.extractLastSMSCode()
	suite.NotEmpty(flowID)
	suite.NotEmpty(sessionCode)
	suite.NotEmpty(code)

	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change/verify", S{
		"flow_id":      flowID,
		"token":        code,
		"session_code": sessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, verifyResponse.ResponseRecorder.Code)
	suite.Nil(verifyResponse.Error)
	suite.Equal(true, verifyResponse.Data.(map[string]any)["completed"])
}

func (suite *SecurePhoneChangeTestSuite) TestSecurePhoneChangeSupportsCurrentPhoneConfirmation() {
	suite.setRequireCurrentPhoneConfirmation(true)

	email := fmt.Sprintf("secure-phone-current-%d@example.com", time.Now().UnixNano())
	currentPhone := "+15555555555"
	accessToken := suite.signUpConfirmAndLogin(email, currentPhone, "SecurePhone123!")
	suite.upgradeToAAL2(accessToken)

	newPhone := "+16666666666"
	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change", S{
		"phone": newPhone,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)

	flowID := suite.helper.MustDataString(suite.T(), startResponse, "flow_id")
	newSessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	newCode := suite.extractLastSMSCode()

	verifyNewResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change/verify", S{
		"flow_id":      flowID,
		"token":        newCode,
		"session_code": newSessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, verifyNewResponse.ResponseRecorder.Code)
	suite.Nil(verifyNewResponse.Error)

	data := verifyNewResponse.Data.(map[string]any)
	suite.Equal(false, data["completed"])
	suite.Equal("verify_current", data["stage"])

	currentSessionCode := data["session_code"].(string)
	currentCode := suite.extractLastSMSCode()
	suite.NotEmpty(currentSessionCode)
	suite.NotEmpty(currentCode)

	verifyCurrentResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change/verify", S{
		"flow_id":      flowID,
		"token":        currentCode,
		"session_code": currentSessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, verifyCurrentResponse.ResponseRecorder.Code)
	suite.Nil(verifyCurrentResponse.Error)
	suite.Equal(true, verifyCurrentResponse.Data.(map[string]any)["completed"])
}

func (suite *SecurePhoneChangeTestSuite) TestSecurePhoneChangeRejectsSamePhoneAndConflict() {
	suite.setRequireCurrentPhoneConfirmation(false)

	email := fmt.Sprintf("secure-phone-same-%d@example.com", time.Now().UnixNano())
	currentPhone := "+17777777777"
	accessToken := suite.signUpConfirmAndLogin(email, currentPhone, "SecurePhone123!")
	suite.upgradeToAAL2(accessToken)

	sameResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change", S{
		"phone": currentPhone,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.NotNil(sameResponse.Error)

	conflictEmail := fmt.Sprintf("secure-phone-conflict-%d@example.com", time.Now().UnixNano())
	conflictPhone := "+18888888888"
	suite.signUpConfirmAndLogin(conflictEmail, conflictPhone, "SecurePhone123!")

	conflictResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/phone/change", S{
		"phone": conflictPhone,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.NotNil(conflictResponse.Error)
	suite.Contains(conflictResponse.Error.Key, "phone_exists")
}

func TestSecurePhoneChangeTestSuite(t *testing.T) {
	suite.Run(t, new(SecurePhoneChangeTestSuite))
}
