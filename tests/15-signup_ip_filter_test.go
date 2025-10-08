package tests

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
)

type SignupIPFilterTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SignupIPFilterTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	suite.setupIPFilterMiddleware()
}

func createIPFilterMiddleware(blockedIPs []string) func(ctx services.SignupContext, next func() error) error {
	return func(ctx services.SignupContext, next func() error) error {

		clientIP := getClientIP(ctx.HttpRequest())

		for _, blockedIP := range blockedIPs {
			if clientIP == blockedIP {
				return consts.UNEXPECTED_FAILURE
			}
		}

		return next()
	}
}

func getClientIP(r *http.Request) string {

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {

		if commaIndex := len(xff); commaIndex > 0 {
			for i, char := range xff {
				if char == ',' {
					commaIndex = i
					break
				}
			}
			firstIP := xff[:commaIndex]
			if ip := net.ParseIP(firstIP); ip != nil {
				return ip.String()
			}
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (suite *SignupIPFilterTestSuite) setupIPFilterMiddleware() {

	blockedIPs := []string{"192.168.1.100", "10.0.0.50"}

	ipFilterMiddleware := createIPFilterMiddleware(blockedIPs)

	suite.AuthService.SignupUse(ipFilterMiddleware)
}

func (suite *SignupIPFilterTestSuite) TestSignupWithAllowedIP() {
	email := "allowed@example.com"

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequestWithIP(suite.T(), "/auth/signup", requestBody, "192.168.1.101")
	response.Print()

	suite.Equal(200, response.ResponseRecorder.Code, "Allowed IP should be able to signup successfully")
	suite.Nil(response.Response.Error, "Should not have error")

	suite.NotNil(response.Response.Data, "Should return data")
	responseData := response.Response.Data.(map[string]any)
	suite.Contains(responseData, "user", "Response should contain user")

	userData := responseData["user"].(map[string]any)
	suite.Equal(email, userData["email"], "Email should match")
	suite.NotEmpty(userData["id"], "User ID should not be empty")
}

func (suite *SignupIPFilterTestSuite) TestSignupWithBlockedIP() {
	email := "blocked@example.com"

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequestWithIP(suite.T(), "/auth/signup", requestBody, "192.168.1.100")

	suite.helper.HasError(suite.T(), response, "unexpected_failure", "Blocked IP should return error")

	var count int64
	err := suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND instance_id = ?", email, suite.TestInstance).Scan(&count).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), count, "User should not be created with blocked IP")
}

func (suite *SignupIPFilterTestSuite) TestSignupWithAnotherBlockedIP() {
	email := "blocked2@example.com"

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequestWithIP(suite.T(), "/auth/signup", requestBody, "10.0.0.50")

	suite.helper.HasError(suite.T(), response, "unexpected_failure", "Another blocked IP should return error")

	var count int64
	err := suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND instance_id = ?", email, suite.TestInstance).Scan(&count).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), count, "User should not be created with blocked IP")
}

func (suite *SignupIPFilterTestSuite) TestSignupWithXForwardedForHeader() {
	email := "xforwarded@example.com"

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequestWithHeaders(suite.T(), "/auth/signup", requestBody, map[string]string{
		"X-Forwarded-For": "192.168.1.100",
	})

	suite.helper.HasError(suite.T(), response, "unexpected_failure", "X-Forwarded-For header with blocked IP should return error")

	var count int64
	err := suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND instance_id = ?", email, suite.TestInstance).Scan(&count).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), count, "User should not be created with blocked IP in X-Forwarded-For header")
}

func TestSignupIPFilterTestSuite(t *testing.T) {
	suite.Run(t, new(SignupIPFilterTestSuite))
}
