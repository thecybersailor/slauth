package tests

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/config"
)

type SecureEmailChangeTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SecureEmailChangeTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

func (suite *SecureEmailChangeTestSuite) extractLastEmailCode() string {
	re := regexp.MustCompile(`\b\d{6}\b`)
	if lastEmail := suite.helper.GetMockEmailProvider().GetLastEmail(); lastEmail != nil {
		return re.FindString(lastEmail.Body)
	}
	return ""
}

func (suite *SecureEmailChangeTestSuite) signUpConfirmAndLogin(email, password string) string {
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
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

func (suite *SecureEmailChangeTestSuite) upgradeToAAL2(accessToken string) {
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

func (suite *SecureEmailChangeTestSuite) setRequireCurrentEmailConfirmation(enabled bool) {
	update := config.NewDefaultAuthServiceConfig()
	update.SecurityConfig = &config.SecurityConfig{
		EmailChangeConfig: config.IdentityChangeConfig{
			RequiredAAL:                     update.SecurityConfig.EmailChangeConfig.RequiredAAL,
			RequireCurrentValueConfirmation: enabled,
			RateLimit:                       update.SecurityConfig.EmailChangeConfig.RateLimit,
		},
	}
	suite.Require().NoError(suite.AuthService.SaveConfig(update))
}

func (suite *SecureEmailChangeTestSuite) TestSecureEmailChangeRequiresAAL2() {
	email := fmt.Sprintf("secure-email-aal-%d@example.com", time.Now().UnixNano())
	accessToken := suite.signUpConfirmAndLogin(email, "SecureEmail123!")

	response := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change", S{
		"email": fmt.Sprintf("next-%d@example.com", time.Now().UnixNano()),
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})

	suite.NotNil(response.Error)
	suite.Contains(response.Error.Key, "insufficient_aal")
}

func (suite *SecureEmailChangeTestSuite) TestSecureEmailChangeStartsFlowAndVerifiesNewEmail() {
	suite.setRequireCurrentEmailConfirmation(false)

	email := fmt.Sprintf("secure-email-start-%d@example.com", time.Now().UnixNano())
	accessToken := suite.signUpConfirmAndLogin(email, "SecureEmail123!")
	suite.upgradeToAAL2(accessToken)

	newEmail := fmt.Sprintf("secure-email-next-%d@example.com", time.Now().UnixNano())
	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change", S{
		"email": newEmail,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)
	suite.Nil(startResponse.Error)

	flowID := suite.helper.MustDataString(suite.T(), startResponse, "flow_id")
	sessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	code := suite.extractLastEmailCode()
	suite.NotEmpty(flowID)
	suite.NotEmpty(sessionCode)
	suite.NotEmpty(code)

	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change/verify", S{
		"flow_id":      flowID,
		"token":        code,
		"session_code": sessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, verifyResponse.ResponseRecorder.Code)
	suite.Nil(verifyResponse.Error)

	data := verifyResponse.Data.(map[string]any)
	suite.Equal(true, data["completed"])

	loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", S{
		"grant_type": "password",
		"email":      newEmail,
		"password":   "SecureEmail123!",
	})
	suite.Equal(200, loginResponse.ResponseRecorder.Code)
	suite.Nil(loginResponse.Error)
}

func (suite *SecureEmailChangeTestSuite) TestSecureEmailChangeSupportsCurrentEmailConfirmation() {
	suite.setRequireCurrentEmailConfirmation(true)

	email := fmt.Sprintf("secure-email-current-%d@example.com", time.Now().UnixNano())
	accessToken := suite.signUpConfirmAndLogin(email, "SecureEmail123!")
	suite.upgradeToAAL2(accessToken)

	newEmail := fmt.Sprintf("secure-email-current-next-%d@example.com", time.Now().UnixNano())
	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change", S{
		"email": newEmail,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)

	flowID := suite.helper.MustDataString(suite.T(), startResponse, "flow_id")
	newSessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	newCode := suite.extractLastEmailCode()

	verifyNewResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change/verify", S{
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
	currentCode := suite.extractLastEmailCode()
	suite.NotEmpty(currentSessionCode)
	suite.NotEmpty(currentCode)

	verifyCurrentResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change/verify", S{
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

func (suite *SecureEmailChangeTestSuite) TestSecureEmailChangeRejectsSameEmailAndConflict() {
	suite.setRequireCurrentEmailConfirmation(false)

	email := fmt.Sprintf("secure-email-same-%d@example.com", time.Now().UnixNano())
	accessToken := suite.signUpConfirmAndLogin(email, "SecureEmail123!")
	suite.upgradeToAAL2(accessToken)

	sameResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change", S{
		"email": email,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.NotNil(sameResponse.Error)

	conflictEmail := fmt.Sprintf("secure-email-conflict-%d@example.com", time.Now().UnixNano())
	suite.signUpConfirmAndLogin(conflictEmail, "SecureEmail123!")

	conflictResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/email/change", S{
		"email": conflictEmail,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.NotNil(conflictResponse.Error)
	suite.Contains(conflictResponse.Error.Key, "email_exists")
}

func TestSecureEmailChangeTestSuite(t *testing.T) {
	suite.Run(t, new(SecureEmailChangeTestSuite))
}
