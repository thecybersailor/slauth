package tests

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
)

type AdvancedAdminTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *AdvancedAdminTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

func TestAdvancedAdminTestSuite(t *testing.T) {
	suite.Run(t, new(AdvancedAdminTestSuite))
}

func (suite *AdvancedAdminTestSuite) TestCreateAndLogin() {
	createUserData := S{
		"email":           "admin-test@example.com",
		"phone":           "+1234567890",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"phone_confirmed": false,
		"user_data": S{
			"name": "Admin Test User",
			"role": "user",
		},
		"app_metadata": S{
			"role":        "admin",
			"department":  "IT",
			"permissions": []string{"read", "write", "admin"},
		},
	}

	createResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData)
	suite.Equal(200, createResp.ResponseRecorder.Code, "Create user should succeed")
	suite.Nil(createResp.Error, "Create user should not have error")

	createResp.Print()

	suite.NotNil(createResp.Data, "Create user should return data")

	userData := createResp.Data.(map[string]interface{})
	userID := userData["id"].(string)
	suite.NotEmpty(userID, "User ID should not be empty")

	loginData := S{
		"grant_type": "password",
		"email":      "admin-test@example.com",
		"password":   "TestPassword123!",
	}

	loginResp := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginData)
	suite.Equal(200, loginResp.ResponseRecorder.Code, "Login should succeed")
	suite.Nil(loginResp.Error, "Login should not have error")

	loginResp.Print()

	suite.NotNil(loginResp.Data, "Login should return data")
	loginData2 := loginResp.Data.(map[string]interface{})
	suite.Contains(loginData2, "session", "Login response should contain session")

	sessionData := loginData2["session"].(map[string]interface{})
	suite.Contains(sessionData, "access_token", "Session should contain access_token")

	accessToken := sessionData["access_token"].(string)

	userResp := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", accessToken)
	suite.Equal(200, userResp.ResponseRecorder.Code, "Get user should succeed")
	suite.Nil(userResp.Error, "Get user should not have error")

	userResp.Print()

	suite.NotNil(userResp.Data, "Get user should return data")

	sessionsResp := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/sessions", accessToken)
	suite.Equal(200, sessionsResp.ResponseRecorder.Code, "Get sessions should succeed")
	suite.Nil(sessionsResp.Error, "Get sessions should not have error")

	sessionsResp.Print()

	suite.NotNil(sessionsResp.Data, "Get sessions should return data")
}

func (suite *AdvancedAdminTestSuite) TestListUsers() {
	users := []map[string]interface{}{
		{
			"email":           "list-user1@example.com",
			"phone":           "+1111111111",
			"password":        "TestPassword123!",
			"email_confirmed": true,
			"phone_confirmed": false,
			"user_data": S{
				"name": "List User 1",
				"role": "user",
			},
		},
		{
			"email":           "list-user2@example.com",
			"phone":           "+2222222222",
			"password":        "TestPassword123!",
			"email_confirmed": false,
			"phone_confirmed": true,
			"user_data": S{
				"name": "List User 2",
				"role": "admin",
			},
		},
		{
			"email":           "list-user3@example.com",
			"phone":           "+3333333333",
			"password":        "TestPassword123!",
			"email_confirmed": true,
			"phone_confirmed": true,
			"user_data": S{
				"name": "List User 3",
				"role": "moderator",
			},
		},
	}

	for i, userData := range users {
		createResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", userData)
		suite.Equal(200, createResp.ResponseRecorder.Code, "Create user %d should succeed", i+1)
		suite.Nil(createResp.Error, "Create user %d should not have error", i+1)
	}

	listResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	})
	suite.Equal(200, listResp.ResponseRecorder.Code, "List users should succeed")
	suite.Nil(listResp.Error, "List users should not have error")

	listResp.Print()

	suite.NotNil(listResp.Data, "List users should return data")
	listData := listResp.Data.(map[string]interface{})

	suite.Contains(listData, "users", "Response should contain users array")
	suite.Contains(listData, "page", "Response should contain page")
	suite.Contains(listData, "page_size", "Response should contain page_size")
	suite.Contains(listData, "total", "Response should contain total")

	usersArray := listData["users"].([]interface{})
	suite.GreaterOrEqual(len(usersArray), 3, "Should have at least 3 users (the ones we created)")

	for i, userInterface := range usersArray {
		user := userInterface.(map[string]interface{})
		suite.Contains(user, "id", "User %d should have id", i)
		suite.Contains(user, "email", "User %d should have email", i)
		suite.Contains(user, "created_at", "User %d should have created_at", i)

		userID := user["id"].(string)
		suite.NotEmpty(userID, "User %d ID should not be empty", i)
	}

	listRespPage2 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"pagination": S{
			"page":     2,
			"pageSize": 2,
		},
	})
	suite.Equal(200, listRespPage2.ResponseRecorder.Code, "List users page 2 should succeed")
	suite.Nil(listRespPage2.Error, "List users page 2 should not have error")

	filterResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"filters": S{
			"email": S{
				"$eq": "list-user1@example.com",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	})
	suite.Equal(200, filterResp.ResponseRecorder.Code, "Filter users by email should succeed")
	suite.Nil(filterResp.Error, "Filter users by email should not have error")

	filterData := filterResp.Data.(map[string]interface{})
	filteredUsers := filterData["users"].([]interface{})
	suite.GreaterOrEqual(len(filteredUsers), 1, "Should return at least 1 user")

	foundTargetUser := false
	for _, userInterface := range filteredUsers {
		user := userInterface.(map[string]interface{})
		if user["email"] == "list-user1@example.com" {
			foundTargetUser = true
			break
		}
	}
	suite.True(foundTargetUser, "Should find the target user in filter results")
}

func (suite *TestSuite) TestCreateUserWithDuplicateEmail() {

}

func (suite *TestSuite) TestUpdateUser() {

}

func (suite *TestSuite) TestUpdateUserPassword() {

}

func (suite *TestSuite) TestUpdateUserEmailAndPhone() {

}

func (suite *TestSuite) TestDeleteUser() {

}

func (suite *TestSuite) TestListUserIdentities() {

}

func (suite *TestSuite) TestDeleteUserIdentity() {

}

func (suite *TestSuite) TestGetAuditLog() {

}

func (suite *TestSuite) TestGetDevices() {

}

func (suite *TestSuite) TestDeleteNonExistentUser() {

}

func (suite *TestSuite) TestCreateUserWithInvalidPassword() {

}

func (suite *TestSuite) TestUpdateUserWithInvalidData() {

}

func (suite *TestSuite) TestUpdateNonExistentUser() {

}

func (suite *TestSuite) TestCreateUserLoginWithWrongPassword() {

}

func (suite *TestSuite) TestOAuthLoginCreatesIdentity() {
	// Create helper for this test
	helper := NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Setup: Add mock OAuth provider
	mockProvider := NewMockOAuthProviderWithFlow("mock-oauth-identity", "auth_code")
	suite.AuthService.AddIdentityProvider(mockProvider)

	// Step 1: Initiate OAuth flow
	oauthRequestBody := S{
		"provider": "mock-oauth-identity",
		"options":  S{},
	}

	oauthResponse := helper.MakePOSTRequest(suite.T(), "/auth/authorize", oauthRequestBody)
	suite.Equal(200, oauthResponse.ResponseRecorder.Code, "OAuth authorize should succeed")
	suite.Nil(oauthResponse.Error, "OAuth authorize should not have error")

	responseData := oauthResponse.Data.(map[string]any)
	flowID := responseData["flow_id"].(string)
	suite.NotEmpty(flowID, "Should have flow_id")

	// Step 2: Exchange code for token (PKCE flow)
	exchangeRequestBody := S{
		"auth_code":     "mock-auth-code-123",
		"code_verifier": "mock-code-verifier-123",
		"flow_id":       flowID,
	}

	exchangeResponse := helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=pkce", exchangeRequestBody)
	suite.Equal(200, exchangeResponse.ResponseRecorder.Code, "PKCE code exchange should succeed")
	suite.Nil(exchangeResponse.Error, "PKCE code exchange should not have error")

	exchangeData := exchangeResponse.Data.(map[string]any)
	userInfo := exchangeData["user"].(map[string]any)
	userID := userInfo["id"].(string)
	suite.NotEmpty(userID, "User should have ID")

	// Step 3: Verify identity was created in database
	var identityCount int64
	err := suite.DB.Model(&models.Identity{}).
		Where("instance_id = ? AND provider = ? AND provider_id = ?",
			suite.TestInstance, "mock-oauth-identity", "mock-user-123").
		Count(&identityCount).Error
	suite.NoError(err, "Should be able to query identities table")
	suite.Equal(int64(1), identityCount, "Should create exactly one identity record")

	// Step 4: Verify identity details
	var identity models.Identity
	err = suite.DB.Model(&models.Identity{}).
		Where("instance_id = ? AND provider = ? AND provider_id = ?",
			suite.TestInstance, "mock-oauth-identity", "mock-user-123").
		First(&identity).Error
	suite.NoError(err, "Should find the identity record")
	suite.Equal("mock-oauth-identity", identity.Provider, "Provider should match")
	suite.Equal("mock-user-123", identity.ProviderID, "Provider ID should match")
	suite.Equal("mock-user@example.com", *identity.Email, "Email should match")

	// Step 5: Verify user response includes identities
	suite.NotNil(userInfo["identities"], "User response should include identities field")
	identities, ok := userInfo["identities"].([]any)
	suite.True(ok, "Identities should be an array")
	suite.Greater(len(identities), 0, "Should have at least one identity")
	
	// Find the identity with provider "mock-oauth-identity"
	found := false
	for _, id := range identities {
		identityData := id.(map[string]any)
		if identityData["provider"] == "mock-oauth-identity" {
			found = true
			suite.Equal("mock-oauth-identity", identityData["provider"], "Identity provider should match in response")
			break
		}
	}
	suite.True(found, "Should find identity with provider 'mock-oauth-identity' in response")
}

func (suite *TestSuite) TestAdminUserManagementPermissions() {

}

func (suite *AdvancedAdminTestSuite) TestCreateUserWithAppMetadata() {
	createUserData := S{
		"email":           "appmeta-user@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"phone_confirmed": false,
		"user_data": S{
			"name": "AppMeta User",
			"role": "user",
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
	}

	createResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData)
	suite.Equal(200, createResp.ResponseRecorder.Code, "Create user with AppMetaData should succeed")
	suite.Nil(createResp.Error, "Create user should not have error")

	createResp.Print()

	suite.NotNil(createResp.Data, "Create user should return data")
	userData := createResp.Data.(map[string]interface{})
	suite.Equal("appmeta-user@example.com", userData["email"], "Email should match")
	suite.NotEmpty(userData["id"], "User ID should not be empty")

	suite.Contains(userData, "app_metadata", "Response should contain app_metadata")
	appMetadata := userData["app_metadata"].(map[string]interface{})
	suite.Equal("manager", appMetadata["role"], "AppMetaData role should match")
	suite.Equal("Sales", appMetadata["department"], "AppMetaData department should match")

	var dbUser struct {
		ID             uint `gorm:"primaryKey"`
		Email          string
		RawAppMetaData *[]byte `gorm:"column:raw_app_meta_data"`
	}

	err := suite.DB.Model(&models.User{}).Where("email = ?", "appmeta-user@example.com").First(&dbUser).Error
	suite.NoError(err, "Should be able to query user from database")
	suite.NotNil(dbUser.RawAppMetaData, "RawAppMetaData should not be NULL in database")

	var storedAppMetadata map[string]interface{}
	err = json.Unmarshal(*dbUser.RawAppMetaData, &storedAppMetadata)
	suite.NoError(err, "Should be able to parse stored app metadata JSON")
	suite.Equal("manager", storedAppMetadata["role"], "Stored role should match")
	suite.Equal("Sales", storedAppMetadata["department"], "Stored department should match")
}

func (suite *AdvancedAdminTestSuite) TestGetUserAppMetadata() {
	createUserData := S{
		"email":           "get-appmeta@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"app_metadata": S{
			"role":        "developer",
			"department":  "Engineering",
			"permissions": []string{"read", "write", "code_review"},
			"level":       "senior",
		},
	}

	createResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData)
	suite.Equal(200, createResp.ResponseRecorder.Code, "Create user should succeed")
	userData := createResp.Data.(map[string]interface{})
	userID := userData["id"].(string)

	getResp := suite.helper.MakeGETRequest(suite.T(), "/admin/users/"+userID)
	suite.Equal(200, getResp.ResponseRecorder.Code, "Get user should succeed")
	suite.Nil(getResp.Error, "Get user should not have error")

	getResp.Print()

	suite.NotNil(getResp.Data, "Get user should return data")
	retrievedUser := getResp.Data.(map[string]interface{})
	suite.Contains(retrievedUser, "app_metadata", "Response should contain app_metadata")

	appMetadata := retrievedUser["app_metadata"].(map[string]interface{})
	suite.Equal("developer", appMetadata["role"], "AppMetaData role should match")
	suite.Equal("Engineering", appMetadata["department"], "AppMetaData department should match")
	suite.Equal("senior", appMetadata["level"], "AppMetaData level should match")

	permissions, ok := appMetadata["permissions"].([]interface{})
	suite.True(ok, "Permissions should be an array")
	suite.Contains(permissions, "code_review", "Permissions should contain code_review")
}

func (suite *AdvancedAdminTestSuite) TestUpdateUserAppMetadata() {
	createUserData := S{
		"email":           "update-appmeta@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"app_metadata": S{
			"role":        "junior",
			"department":  "Support",
			"permissions": []string{"read"},
		},
	}

	createResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData)
	suite.Equal(200, createResp.ResponseRecorder.Code, "Create user should succeed")
	userData := createResp.Data.(map[string]interface{})
	userID := userData["id"].(string)

	updateData := S{
		"app_metadata": S{
			"role":        "senior",
			"department":  "Engineering",
			"permissions": []string{"read", "write", "admin", "code_review"},
			"level":       "expert",
			"subscription": S{
				"plan":   "enterprise",
				"status": "active",
			},
		},
	}

	updateResp := suite.helper.MakePUTRequest(suite.T(), "/admin/users/"+userID, updateData, nil)
	suite.Equal(200, updateResp.ResponseRecorder.Code, "Update user AppMetaData should succeed")
	suite.Nil(updateResp.Error, "Update should not have error")

	updateResp.Print()

	suite.NotNil(updateResp.Data, "Update should return data")
	updatedUser := updateResp.Data.(map[string]interface{})
	suite.Contains(updatedUser, "app_metadata", "Response should contain app_metadata")

	appMetadata := updatedUser["app_metadata"].(map[string]interface{})
	suite.Equal("senior", appMetadata["role"], "Updated role should match")
	suite.Equal("Engineering", appMetadata["department"], "Updated department should match")
	suite.Equal("expert", appMetadata["level"], "Updated level should match")

	permissions, ok := appMetadata["permissions"].([]interface{})
	suite.True(ok, "Permissions should be an array")
	suite.Contains(permissions, "admin", "Permissions should contain admin")
	suite.Contains(permissions, "code_review", "Permissions should contain code_review")

	subscription, ok := appMetadata["subscription"].(map[string]interface{})
	suite.True(ok, "Subscription should be a nested object")
	suite.Equal("enterprise", subscription["plan"], "Subscription plan should match")

	var dbUser struct {
		ID             uint `gorm:"primaryKey"`
		Email          string
		RawAppMetaData *[]byte `gorm:"column:raw_app_meta_data"`
	}

	err := suite.DB.Model(&models.User{}).Where("email = ?", "update-appmeta@example.com").First(&dbUser).Error
	suite.NoError(err, "Should be able to query user from database")
	suite.NotNil(dbUser.RawAppMetaData, "RawAppMetaData should not be NULL in database")

	var storedAppMetadata map[string]interface{}
	err = json.Unmarshal(*dbUser.RawAppMetaData, &storedAppMetadata)
	suite.NoError(err, "Should be able to parse stored app metadata JSON")
	suite.Equal("senior", storedAppMetadata["role"], "Stored role should be updated")
	suite.Equal("Engineering", storedAppMetadata["department"], "Stored department should be updated")
}

func (suite *AdvancedAdminTestSuite) TestSearchUsersByAppMetadata() {
	users := []map[string]interface{}{
		{
			"email":           "search-user1@example.com",
			"password":        "TestPassword123!",
			"email_confirmed": true,
			"app_metadata": S{
				"role":        "admin",
				"department":  "IT",
				"permissions": []string{"read", "write", "admin"},
			},
		},
		{
			"email":           "search-user2@example.com",
			"password":        "TestPassword123!",
			"email_confirmed": true,
			"app_metadata": S{
				"role":        "manager",
				"department":  "Sales",
				"permissions": []string{"read", "write", "manage_team"},
			},
		},
		{
			"email":           "search-user3@example.com",
			"password":        "TestPassword123!",
			"email_confirmed": true,
			"app_metadata": S{
				"role":        "admin",
				"department":  "Engineering",
				"permissions": []string{"read", "write", "admin", "code_review"},
			},
		},
	}

	for i, userData := range users {
		createResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", userData)
		suite.Equal(200, createResp.ResponseRecorder.Code, "Create user %d should succeed", i+1)
		suite.Nil(createResp.Error, "Create user %d should not have error", i+1)
	}

	roleSearchResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"filters": S{
			"app_metadata.role": S{
				"$eq": "admin",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	})
	suite.Equal(200, roleSearchResp.ResponseRecorder.Code, "Search by role should succeed")
	suite.Nil(roleSearchResp.Error, "Search by role should not have error")

	roleSearchResp.Print()

	suite.NotNil(roleSearchResp.Data, "Search should return data")
	searchData := roleSearchResp.Data.(map[string]interface{})
	suite.Contains(searchData, "users", "Response should contain users array")

	usersArray := searchData["users"].([]interface{})
	suite.GreaterOrEqual(len(usersArray), 2, "Should find at least 2 admin users")

	for i, userInterface := range usersArray {
		user := userInterface.(map[string]interface{})
		if user["email"] == "search-user1@example.com" || user["email"] == "search-user3@example.com" {
			suite.Contains(user, "app_metadata", "User %d should have app_metadata", i)
			appMetadata := user["app_metadata"].(map[string]interface{})
			suite.Equal("admin", appMetadata["role"], "User %d should have admin role", i)
		}
	}

	deptSearchResp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", S{
		"filters": S{
			"app_metadata.department": S{
				"$eq": "IT",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	})
	suite.Equal(200, deptSearchResp.ResponseRecorder.Code, "Search by department should succeed")
	suite.Nil(deptSearchResp.Error, "Search by department should not have error")

	deptSearchData := deptSearchResp.Data.(map[string]interface{})
	deptUsersArray := deptSearchData["users"].([]interface{})
	suite.GreaterOrEqual(len(deptUsersArray), 1, "Should find at least 1 IT user")

	foundITUser := false
	for _, userInterface := range deptUsersArray {
		user := userInterface.(map[string]interface{})
		if user["email"] == "search-user1@example.com" {
			appMetadata := user["app_metadata"].(map[string]interface{})
			suite.Equal("IT", appMetadata["department"], "User should be in IT department")
			foundITUser = true
			break
		}
	}
	suite.True(foundITUser, "Should find the IT user in search results")
}
