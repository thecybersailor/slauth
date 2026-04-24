package tests

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
)

type ReauthenticationTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *ReauthenticationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	cfg := suite.AuthService.GetConfig()
	trueVal := true
	cfg.ConfirmEmail = &trueVal
	suite.Require().NoError(suite.AuthService.SaveConfig(cfg))
}

func (suite *ReauthenticationTestSuite) extractLastVerificationCode() string {
	re := regexp.MustCompile(`\b\d{6}\b`)
	if lastEmail := suite.helper.GetMockEmailProvider().GetLastEmail(); lastEmail != nil {
		if code := re.FindString(lastEmail.Body); code != "" {
			return code
		}
	}
	if lastSMS := suite.helper.GetMockSMSProvider().GetLastSMS(); lastSMS != nil {
		if code := re.FindString(lastSMS.Body); code != "" {
			return code
		}
	}
	return ""
}

func (suite *ReauthenticationTestSuite) signUpAndLogin(email, password string) string {
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Equal(200, signupResponse.ResponseRecorder.Code)
	suite.Nil(signupResponse.Error)

	lastEmail := suite.helper.GetMockEmailProvider().GetLastEmail()
	suite.Require().NotNil(lastEmail)

	tokenStart := len("token=")
	token := ""
	body := lastEmail.Body
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
	accessToken := session["access_token"].(string)
	suite.NotEmpty(accessToken)
	return accessToken
}

func (suite *ReauthenticationTestSuite) TestReauthenticationSendsChallengeForAuthenticatedUser() {
	email := fmt.Sprintf("reauth-send-%d@example.com", time.Now().UnixNano())
	password := "ReauthPassword123!"
	accessToken := suite.signUpAndLogin(email, password)

	response := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate", S{}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})

	suite.Equal(200, response.ResponseRecorder.Code)
	suite.Nil(response.Error)
	suite.NotEmpty(suite.helper.MustDataString(suite.T(), response, "session_code"))
	suite.NotEmpty(suite.extractLastVerificationCode())
}

func (suite *ReauthenticationTestSuite) TestReauthenticationVerifyUpgradesSessionAAL() {
	email := fmt.Sprintf("reauth-verify-%d@example.com", time.Now().UnixNano())
	password := "ReauthPassword123!"
	accessToken := suite.signUpAndLogin(email, password)

	beforeClaims, err := suite.AuthService.ValidateJWT(accessToken)
	suite.Require().NoError(err)
	suite.Equal(string(types.AALLevel1), fmt.Sprintf("%v", beforeClaims["aal"]))

	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate", S{}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)
	sessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	code := suite.extractLastVerificationCode()
	suite.NotEmpty(sessionCode)
	suite.NotEmpty(code)

	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate/verify", S{
		"token":        code,
		"session_code": sessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, verifyResponse.ResponseRecorder.Code)
	suite.Nil(verifyResponse.Error)

	afterClaims, err := suite.AuthService.ValidateJWT(accessToken)
	suite.Require().NoError(err)
	suite.Equal(string(types.AALLevel2), fmt.Sprintf("%v", afterClaims["aal"]))
}

func (suite *ReauthenticationTestSuite) TestReauthenticationVerifyRejectsExpiredCode() {
	email := fmt.Sprintf("reauth-expired-%d@example.com", time.Now().UnixNano())
	password := "ReauthPassword123!"
	accessToken := suite.signUpAndLogin(email, password)

	startResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate", S{}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	suite.Equal(200, startResponse.ResponseRecorder.Code)
	sessionCode := suite.helper.MustDataString(suite.T(), startResponse, "session_code")
	code := suite.extractLastVerificationCode()
	suite.NotEmpty(code)

	var token models.OneTimeToken
	suite.Require().NoError(
		suite.DB.
			Where("session_code = ? AND instance_id = ? AND token_type = ?", sessionCode, suite.TestInstance, types.OneTimeTokenTypeReauthentication).
			First(&token).Error,
	)
	expiredAt := time.Now().Add(-24 * time.Hour)
	suite.Require().NoError(
		suite.DB.Model(&models.OneTimeToken{}).
			Where("id = ?", token.ID).
			Update("expires_at", &expiredAt).Error,
	)
	var expiredToken models.OneTimeToken
	suite.Require().NoError(suite.DB.First(&expiredToken, token.ID).Error)
	suite.Require().NotNil(expiredToken.ExpiresAt)
	suite.True(expiredToken.ExpiresAt.Before(time.Now()))

	verifyResponse := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/reauthenticate/verify", S{
		"token":        code,
		"session_code": sessionCode,
	}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})

	suite.NotNil(verifyResponse.Error)
	suite.Contains(verifyResponse.Error.Key, "reauthentication_not_valid")
}

func (suite *ReauthenticationTestSuite) TestReauthenticationRejectsUnauthenticatedRequest() {
	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/reauthenticate", S{})
	suite.NotNil(response.Error)
	suite.Contains(response.Error.Key, "no_authorization")
}

func TestReauthenticationTestSuite(t *testing.T) {
	suite.Run(t, new(ReauthenticationTestSuite))
}
