package tests

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
)

type UserMetadataManagementTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *UserMetadataManagementTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Disable email confirmation for testing user metadata
	updateConfigReq := S{
		"config": S{
			"confirm_email": false,
		},
	}
	suite.helper.MakePUTRequest(suite.T(), "/admin/config", updateConfigReq, nil)
}

func TestUserMetadataManagementTestSuite(t *testing.T) {
	suite.Run(t, new(UserMetadataManagementTestSuite))
}

func (suite *UserMetadataManagementTestSuite) TestCreateUserWithUserMetadata() {
	signupData := S{
		"email":    "metadata-user@example.com",
		"password": "TestPassword123!",
		"user_metadata": S{
			"first_name": "John",
			"last_name":  "Doe",
			"avatar_url": "https://example.com/avatar.jpg",
			"department": "Engineering",
			"preferences": S{
				"theme":    "dark",
				"language": "en",
				"timezone": "UTC",
			},
		},
	}

	signupResp := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", signupData)
	suite.Equal(200, signupResp.ResponseRecorder.Code, "Signup should succeed")
	suite.Nil(signupResp.Error, "Signup should not have error")

	signupResp.Print()

	suite.NotNil(signupResp.Data, "Signup should return data")
	signupResponseData := signupResp.Data.(map[string]interface{})
	userData := signupResponseData["user"].(map[string]interface{})

	suite.Equal("metadata-user@example.com", userData["email"], "Email should match")
	suite.NotEmpty(userData["id"], "User ID should not be empty")

	loginData := S{
		"grant_type": "password",
		"email":      "metadata-user@example.com",
		"password":   "TestPassword123!",
	}

	loginResp := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginData)
	suite.Equal(200, loginResp.ResponseRecorder.Code, "Login should succeed")
	suite.Nil(loginResp.Error, "Login should not have error")

	loginResp.Print()

	loginResponseData := loginResp.Data.(map[string]interface{})
	sessionData := loginResponseData["session"].(map[string]interface{})
	accessToken := sessionData["access_token"].(string)

	userInfoResp := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userInfoResp.ResponseRecorder.Code, "Get user info should succeed")
	suite.Nil(userInfoResp.Error, "Get user info should not have error")

	userInfoResp.Print()

	suite.NotNil(userInfoResp.Data, "User info should return data")

	var dbUser struct {
		ID              uint `gorm:"primaryKey"`
		Email           string
		RawUserMetaData *[]byte `gorm:"column:raw_user_meta_data"`
		RawAppMetaData  *[]byte `gorm:"column:raw_app_meta_data"`
	}

	err := suite.DB.Model(&models.User{}).Where("email = ?", "metadata-user@example.com").First(&dbUser).Error
	suite.NoError(err, "Should be able to query user from database")

	suite.T().Logf("Database User ID: %d", dbUser.ID)
	suite.T().Logf("Database Email: %s", dbUser.Email)

	if dbUser.RawUserMetaData != nil {
		suite.T().Logf("Database RawUserMetaData: %s", string(*dbUser.RawUserMetaData))
	} else {
		suite.T().Logf("Database RawUserMetaData: NULL")
	}

	if dbUser.RawAppMetaData != nil {
		suite.T().Logf("Database RawAppMetaData: %s", string(*dbUser.RawAppMetaData))
	} else {
		suite.T().Logf("Database RawAppMetaData: NULL")
	}

	suite.NotNil(dbUser.RawUserMetaData, "RawUserMetaData should not be NULL in database")

	var storedUserMetadata map[string]interface{}
	err = json.Unmarshal(*dbUser.RawUserMetaData, &storedUserMetadata)
	suite.NoError(err, "Should be able to parse stored user metadata JSON")

	suite.Equal("John", storedUserMetadata["first_name"], "first_name should be stored correctly")
	suite.Equal("Doe", storedUserMetadata["last_name"], "last_name should be stored correctly")
	suite.Equal("https://example.com/avatar.jpg", storedUserMetadata["avatar_url"], "avatar_url should be stored correctly")
	suite.Equal("Engineering", storedUserMetadata["department"], "department should be stored correctly")

	preferences, ok := storedUserMetadata["preferences"].(map[string]interface{})
	suite.True(ok, "preferences should be a nested object")
	suite.Equal("dark", preferences["theme"], "theme preference should be stored correctly")
	suite.Equal("en", preferences["language"], "language preference should be stored correctly")
	suite.Equal("UTC", preferences["timezone"], "timezone preference should be stored correctly")
}

func (suite *UserMetadataManagementTestSuite) TestAdminCreateUserWithAppMetadata() {
	adminCreateData := S{
		"email":    "admin-created-user@example.com",
		"password": "AdminPassword123!",
		"user_metadata": S{
			"first_name": "Alice",
			"last_name":  "Smith",
			"avatar_url": "https://example.com/alice.jpg",
		},
		"app_metadata": S{
			"role":        "manager",
			"department":  "Sales",
			"permissions": []string{"read", "write", "manage_team"},
			"subscription": S{
				"plan":   "premium",
				"status": "active",
			},
		},
		"email_confirmed": true,
		"phone_confirmed": false,
	}

	adminCreateResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", adminCreateData)
	suite.Equal(200, adminCreateResp.ResponseRecorder.Code, "Admin create user should succeed")
	suite.Nil(adminCreateResp.Error, "Admin create user should not have error")

	adminCreateResp.Print()

	suite.NotNil(adminCreateResp.Data, "Admin create should return data")
	userData := adminCreateResp.Data.(map[string]interface{})

	suite.Equal("admin-created-user@example.com", userData["email"], "Email should match")
	suite.NotEmpty(userData["id"], "User ID should not be empty")

	loginData := S{
		"grant_type": "password",
		"email":      "admin-created-user@example.com",
		"password":   "AdminPassword123!",
	}

	loginResp := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginData)
	suite.Equal(200, loginResp.ResponseRecorder.Code, "Login should succeed")
	suite.Nil(loginResp.Error, "Login should not have error")

	loginResp.Print()

	loginResponseData := loginResp.Data.(map[string]interface{})
	sessionData := loginResponseData["session"].(map[string]interface{})
	accessToken := sessionData["access_token"].(string)

	userInfoResp := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userInfoResp.ResponseRecorder.Code, "Get user info should succeed")
	suite.Nil(userInfoResp.Error, "Get user info should not have error")

	userInfoResp.Print()

	var dbUser struct {
		ID              uint `gorm:"primaryKey"`
		Email           string
		RawUserMetaData *[]byte `gorm:"column:raw_user_meta_data"`
		RawAppMetaData  *[]byte `gorm:"column:raw_app_meta_data"`
	}

	err := suite.DB.Model(&models.User{}).Where("email = ?", "admin-created-user@example.com").First(&dbUser).Error
	suite.NoError(err, "Should be able to query user from database")

	suite.T().Logf("Database User ID: %d", dbUser.ID)
	suite.T().Logf("Database Email: %s", dbUser.Email)

	if dbUser.RawUserMetaData != nil {
		suite.T().Logf("Database RawUserMetaData: %s", string(*dbUser.RawUserMetaData))
	} else {
		suite.T().Logf("Database RawUserMetaData: NULL")
	}

	if dbUser.RawAppMetaData != nil {
		suite.T().Logf("Database RawAppMetaData: %s", string(*dbUser.RawAppMetaData))
	} else {
		suite.T().Logf("Database RawAppMetaData: NULL")
	}

	suite.NotNil(dbUser.RawUserMetaData, "RawUserMetaData should not be NULL in database")
	suite.NotNil(dbUser.RawAppMetaData, "RawAppMetaData should not be NULL in database")

	var storedUserMetadata map[string]interface{}
	err = json.Unmarshal(*dbUser.RawUserMetaData, &storedUserMetadata)
	suite.NoError(err, "Should be able to parse stored user metadata JSON")

	var storedAppMetadata map[string]interface{}
	err = json.Unmarshal(*dbUser.RawAppMetaData, &storedAppMetadata)
	suite.NoError(err, "Should be able to parse stored app metadata JSON")

	suite.Equal("Alice", storedUserMetadata["first_name"], "first_name should be stored correctly")
	suite.Equal("Smith", storedUserMetadata["last_name"], "last_name should be stored correctly")
	suite.Equal("https://example.com/alice.jpg", storedUserMetadata["avatar_url"], "avatar_url should be stored correctly")

	suite.Equal("manager", storedAppMetadata["role"], "role should be stored correctly")
	suite.Equal("Sales", storedAppMetadata["department"], "department should be stored correctly")

	subscription, ok := storedAppMetadata["subscription"].(map[string]interface{})
	suite.True(ok, "subscription should be a nested object")
	suite.Equal("premium", subscription["plan"], "subscription plan should be stored correctly")
	suite.Equal("active", subscription["status"], "subscription status should be stored correctly")
}

func (suite *TestSuite) TestUpdateUserMetadata() {

}

func (suite *TestSuite) TestAdminUpdateUserAppMetadata() {

}

func (suite *TestSuite) TestMetadataInJWTClaims() {

}

func (suite *TestSuite) TestMetadataSearchAndQuery() {

}

func (suite *TestSuite) TestMetadataPermissionsAndSecurity() {

}

func (suite *TestSuite) TestInvalidMetadataFormats() {

}

func (suite *TestSuite) TestMetadataPermissionViolations() {

}
