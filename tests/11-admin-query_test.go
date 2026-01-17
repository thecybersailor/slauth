package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
)

type AdminQueryTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *AdminQueryTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	suite.createTestUsers()
}

func (suite *AdminQueryTestSuite) createTestUsers() {

	createUserData1 := S{
		"email":           "query-admin@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"app_metadata": S{
			"role":       "admin",
			"level":      "senior",
			"department": "Engineering",
		},
	}

	resp1 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData1)
	suite.Require().Equal(200, resp1.ResponseRecorder.Code, "Create user 1 should succeed")

	loginAdmin := S{
		"grant_type": "password",
		"email":      "query-admin@example.com",
		"password":   "TestPassword123!",
	}
	loginResp := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginAdmin)
	suite.Require().Equal(200, loginResp.ResponseRecorder.Code, "Admin login should succeed")

	createUserData2 := S{
		"email":           "query-user@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"app_metadata": S{
			"role":       "user",
			"level":      "junior",
			"department": "Sales",
		},
	}

	resp2 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData2)
	suite.Require().Equal(200, resp2.ResponseRecorder.Code, "Create user 2 should succeed")

	loginUser := S{
		"grant_type": "password",
		"email":      "query-user@example.com",
		"password":   "TestPassword123!",
	}
	loginResp2 := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginUser)
	suite.Require().Equal(200, loginResp2.ResponseRecorder.Code, "User login should succeed")

	createUserData3 := S{
		"email":           "query-manager@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": false,
		"app_metadata": S{
			"role":       "manager",
			"level":      "senior",
			"department": "Engineering",
		},
	}

	resp3 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData3)
	suite.Require().Equal(200, resp3.ResponseRecorder.Code, "Create user 3 should succeed")

	createUserData4 := S{
		"email":           "query-guest@example.com",
		"password":        "TestPassword123!",
		"email_confirmed": true,
		"app_metadata": S{
			"role":       "guest",
			"level":      "junior",
			"department": "Marketing",
		},
	}

	resp4 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users", createUserData4)
	suite.Require().Equal(200, resp4.ResponseRecorder.Code, "Create user 4 should succeed")

	suite.createOAuthUser()
}

func (suite *AdminQueryTestSuite) createOAuthUser() {
	mockProvider := NewMockOAuthProvider("mock-oauth")
	suite.AuthService.AddIdentityProvider(mockProvider)

	loginData := S{
		"provider": "mock-oauth",
		"credential": S{
			"credential": "mock-jwt-token-oauth-user",
			"client_id":  "mock-client-id",
		},
	}

	oauthResp := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=id_token", loginData)
	suite.Require().Equal(200, oauthResp.ResponseRecorder.Code, "OAuth user creation should succeed")
	suite.Require().Nil(oauthResp.Response.Error, "OAuth user creation should not have error")

	suite.Require().NotNil(oauthResp.Response.Data, "OAuth login should have data")
	responseData := oauthResp.Response.Data.(map[string]interface{})
	userInfo := responseData["user"].(map[string]interface{})
	suite.Equal("mock-user@example.com", userInfo["email"], "OAuth user email should match")

	var userID uint
	err := suite.DB.Model(&models.User{}).
		Where("email = ?", "mock-user@example.com").
		Pluck("id", &userID).Error
	suite.Require().NoError(err, "Should get OAuth user ID")
	suite.Require().NotZero(userID, "OAuth user ID should not be zero")

	// OAuth login already creates identity automatically, so we just verify it exists
	var identityCount int64
	err = suite.DB.Model(&models.Identity{}).
		Where("provider = ? AND user_id = ?", "mock-oauth", userID).
		Count(&identityCount).Error
	suite.Require().NoError(err, "Should query identities")
	suite.Require().Equal(int64(1), identityCount, "Should have 1 identity for OAuth user (created automatically by OAuth login)")
}

func TestAdminQueryTestSuite(t *testing.T) {
	suite.Run(t, new(AdminQueryTestSuite))
}

func (suite *AdminQueryTestSuite) TestBasicQuery() {
	queryData := S{
		"filters": S{
			"email": S{
				"$eq": "query-admin@example.com",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Basic query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(1),
		"users": []interface{}{
			S{
				"email":           "query-admin@example.com",
				"email_confirmed": true,
				"app_metadata": S{
					"role":       "admin",
					"level":      "senior",
					"department": "Engineering",
				},
			},
		},
	}, "Basic query should match exact user")
}

func (suite *AdminQueryTestSuite) TestContainsQuery() {
	queryData := S{
		"filters": S{
			"email": S{
				"$contains": "query",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Contains query should succeed")
	resp.Print()

	data := resp.Response.Data.(map[string]interface{})
	users := data["users"].([]interface{})
	suite.GreaterOrEqual(len(users), 4, "Should find at least 4 users with 'query' in email")
}

func (suite *AdminQueryTestSuite) TestInQuery() {
	queryData := S{
		"filters": S{
			"email": S{
				"$in": []string{
					"query-admin@example.com",
					"query-manager@example.com",
				},
			},
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "$in query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(2),
		"users": []interface{}{
			S{
				"email":           "query-admin@example.com",
				"email_confirmed": true,
				"app_metadata": S{
					"role":       "admin",
					"level":      "senior",
					"department": "Engineering",
				},
			},
			S{
				"email":           "query-manager@example.com",
				"email_confirmed": false,
				"app_metadata": S{
					"role":       "manager",
					"level":      "senior",
					"department": "Engineering",
				},
			},
		},
	}, "$in query should match two users")
}

func (suite *AdminQueryTestSuite) TestAndQuery() {
	queryData := S{
		"filters": S{
			"$and": []interface{}{
				S{
					"email": S{
						"$contains": "query",
					},
				},
				S{
					"email_confirmed_at": S{
						"$exists": true,
					},
				},
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "$and query should succeed")
	resp.Print()

	data := resp.Response.Data.(map[string]interface{})
	users := data["users"].([]interface{})
	suite.GreaterOrEqual(len(users), 3, "Should find at least 3 confirmed users")

	for _, u := range users {
		user := u.(map[string]interface{})
		suite.True(user["email_confirmed"].(bool), "All users should be email confirmed")
	}
}

func (suite *AdminQueryTestSuite) TestOrQuery() {
	queryData := S{
		"filters": S{
			"$or": []interface{}{
				S{
					"email": S{
						"$eq": "query-admin@example.com",
					},
				},
				S{
					"email": S{
						"$eq": "query-guest@example.com",
					},
				},
			},
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "$or query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(2),
		"users": []interface{}{
			S{
				"email":           "query-admin@example.com",
				"email_confirmed": true,
			},
			S{
				"email":           "query-guest@example.com",
				"email_confirmed": true,
			},
		},
	}, "$or query should match two users")
}

func (suite *AdminQueryTestSuite) TestNestedFieldQuery() {

	suite.T().Skip("Nested JSON field queries require special handling for different databases")
}

func (suite *AdminQueryTestSuite) TestComplexQuery() {
	queryData := S{
		"filters": S{
			"$and": []interface{}{
				S{
					"email": S{
						"$contains": "query",
					},
				},
				S{
					"$or": []interface{}{
						S{
							"email_confirmed_at": S{
								"$exists": true,
							},
						},
						S{
							"phone_confirmed_at": S{
								"$exists": true,
							},
						},
					},
				},
			},
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 10,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Complex query should succeed")
	resp.Print()

	data := resp.Response.Data.(map[string]interface{})
	users := data["users"].([]interface{})
	suite.GreaterOrEqual(len(users), 1, "Should find at least 1 user")
}

func (suite *AdminQueryTestSuite) TestSorting() {

	queryData := S{
		"filters": S{
			"email": S{
				"$contains": "query",
			},
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 10,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Sorting query should succeed")
	resp.Print()

	data := resp.Response.Data.(map[string]interface{})
	users := data["users"].([]interface{})

	if len(users) >= 2 {
		email1 := users[0].(map[string]interface{})["email"].(string)
		email2 := users[1].(map[string]interface{})["email"].(string)
		suite.True(email1 < email2, "Users should be sorted by email ascending")
	}
}

func (suite *AdminQueryTestSuite) TestPagination() {

	queryData1 := S{
		"filters": S{
			"email": S{
				"$contains": "query",
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 2,
		},
	}

	resp1 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData1)
	suite.Equal(200, resp1.ResponseRecorder.Code, "Page 1 should succeed")

	data1 := resp1.Response.Data.(map[string]interface{})
	users1 := data1["users"].([]interface{})
	suite.LessOrEqual(len(users1), 2, "Page 1 should have at most 2 users")

	queryData2 := S{
		"filters": S{
			"email": S{
				"$contains": "query",
			},
		},
		"pagination": S{
			"page":     2,
			"pageSize": 2,
		},
	}

	resp2 := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData2)
	suite.Equal(200, resp2.ResponseRecorder.Code, "Page 2 should succeed")

	data2 := resp2.Response.Data.(map[string]interface{})
	users2 := data2["users"].([]interface{})
	suite.LessOrEqual(len(users2), 2, "Page 2 should have at most 2 users")

	if len(users1) > 0 && len(users2) > 0 {
		email1 := users1[0].(map[string]interface{})["email"].(string)
		email2 := users2[0].(map[string]interface{})["email"].(string)
		suite.NotEqual(email1, email2, "Pages should return different users")
	}
}

func (suite *AdminQueryTestSuite) TestEmptyFilters() {
	queryData := S{
		"filters": S{},
		"pagination": S{
			"page":     1,
			"pageSize": 10,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Empty filters should succeed")
	resp.Print()

	data := resp.Response.Data.(map[string]interface{})
	users := data["users"].([]interface{})
	suite.GreaterOrEqual(len(users), 4, "Should return all test users")
}

func (suite *AdminQueryTestSuite) TestDefaultPagination() {
	queryData := S{
		"filters": S{},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Query without pagination should succeed")
	resp.Print()

	data := resp.Response.Data.(map[string]interface{})
	suite.Equal(float64(1), data["page"], "Default page should be 1")
	suite.Equal(float64(20), data["page_size"], "Default page_size should be 20")
}

func (suite *AdminQueryTestSuite) TestCreatedAtQuery() {

	oneHourAgo := time.Now().Add(-1 * time.Hour).Unix()

	queryData := S{
		"filters": S{
			"created_at": S{
				"$gte": oneHourAgo,
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Created at query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(5),
	}, "Should find all recently created users")
}

func (suite *AdminQueryTestSuite) TestCreatedAtRangeQuery() {
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour).Unix()
	tomorrow := now.Add(24 * time.Hour).Unix()

	queryData := S{
		"filters": S{
			"$and": []interface{}{
				S{"created_at": S{"$gte": yesterday}},
				S{"created_at": S{"$lte": tomorrow}},
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Time range query should succeed")

	data := resp.Response.Data.(map[string]interface{})
	total := data["total"].(float64)
	suite.GreaterOrEqual(total, float64(4), "Should find all users created today")
}

func (suite *AdminQueryTestSuite) TestLastSignInExistsQuery() {
	queryData := S{
		"filters": S{
			"last_sign_in_at": S{
				"$exists": true,
			},
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Last sign in exists query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(2),
		"users": []interface{}{
			S{
				"email":           "query-admin@example.com",
				"email_confirmed": true,
				"app_metadata": S{
					"role":       "admin",
					"level":      "senior",
					"department": "Engineering",
				},
			},
			S{
				"email":           "query-user@example.com",
				"email_confirmed": true,
				"app_metadata": S{
					"role":       "user",
					"level":      "junior",
					"department": "Sales",
				},
			},
		},
	}, "Should find users with login records")
}

func (suite *AdminQueryTestSuite) TestNeverSignedInQuery() {
	queryData := S{
		"filters": S{
			"last_sign_in_at": S{
				"$null": true,
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Never signed in query should succeed")

	data := resp.Response.Data.(map[string]interface{})
	total := data["total"].(float64)
	suite.GreaterOrEqual(total, float64(2), "Should find at least 2 users who never signed in (Manager, Guest)")
}

func (suite *AdminQueryTestSuite) TestComplexTimeAndMetadataQuery() {
	oneHourAgo := time.Now().Add(-1 * time.Hour).Unix()

	queryData := S{
		"filters": S{
			"$and": []interface{}{
				S{"created_at": S{"$gte": oneHourAgo}},
				S{"last_sign_in_at": S{"$exists": true}},
				S{"email": S{"$contains": "admin"}},
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Complex query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(1),
		"users": []interface{}{
			S{
				"email":           "query-admin@example.com",
				"email_confirmed": true,
				"app_metadata": S{
					"role":       "admin",
					"level":      "senior",
					"department": "Engineering",
				},
			},
		},
	}, "Complex query should match exact user")
}

func (suite *AdminQueryTestSuite) TestLastSignInTimeRangeQuery() {
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute).Unix()
	future := time.Now().Add(1 * time.Hour).Unix()

	queryData := S{
		"filters": S{
			"$and": []interface{}{
				S{"last_sign_in_at": S{"$gte": fiveMinutesAgo}},
				S{"last_sign_in_at": S{"$lte": future}},
			},
		},
		"sort": []string{"last_sign_in_at desc"},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Last sign in time range query should succeed")

	data := resp.Response.Data.(map[string]interface{})
	total := data["total"].(float64)
	suite.Equal(float64(2), total, "Should find 2 users who signed in recently")

	users := data["users"].([]interface{})
	suite.Equal(2, len(users), "Should return 2 users")

	if len(users) >= 2 {
		user1 := users[0].(map[string]interface{})
		user2 := users[1].(map[string]interface{})
		suite.NotNil(user1["last_sign_in_at"], "User 1 should have last_sign_in_at")
		suite.NotNil(user2["last_sign_in_at"], "User 2 should have last_sign_in_at")
	}
}

func (suite *AdminQueryTestSuite) TestHasIdentitiesQuery() {

	queryData := S{
		"filters": S{
			"has_identities": true,
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Has identities query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(1),
		"users": []interface{}{
			S{
				"email": "mock-user@example.com",
			},
		},
	}, "Should find user with OAuth identity")
}

func (suite *AdminQueryTestSuite) TestNoIdentitiesQuery() {

	queryData := S{
		"filters": S{
			"has_identities": false,
		},
		"sort": []string{"email asc"},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "No identities query should succeed")

	data := resp.Response.Data.(map[string]interface{})
	total := data["total"].(float64)
	suite.GreaterOrEqual(total, float64(4), "Should find at least 4 users without identities")

	users := data["users"].([]interface{})
	suite.GreaterOrEqual(len(users), 4, "Should return at least 4 users")

	for _, u := range users {
		user := u.(map[string]interface{})
		email := user["email"].(string)
		suite.Contains([]string{
			"query-admin@example.com",
			"query-user@example.com",
			"query-manager@example.com",
			"query-guest@example.com",
		}, email, "User should be one of the password-registered users")
	}
}

func (suite *AdminQueryTestSuite) TestCombineIdentitiesAndTimeQuery() {
	oneHourAgo := time.Now().Add(-1 * time.Hour).Unix()

	queryData := S{
		"filters": S{
			"$and": []interface{}{
				S{"created_at": S{"$gte": oneHourAgo}},
				S{"has_identities": true},
			},
		},
		"pagination": S{
			"page":     1,
			"pageSize": 20,
		},
	}

	resp := suite.helper.MakePOSTRequest(suite.T(), "/admin/users/query", queryData)
	suite.Equal(200, resp.ResponseRecorder.Code, "Combined query should succeed")

	suite.helper.MatchObject(suite.T(), resp, S{
		"total": float64(1),
		"users": []interface{}{
			S{
				"email": "mock-user@example.com",
			},
		},
	}, "Should find recently created OAuth user")
}
