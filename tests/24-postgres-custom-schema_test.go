package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type PostgresCustomSchemaTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *PostgresCustomSchemaTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestCustomSchemaVerification verifies that PostgreSQL supports custom schema
// Tests that tables are created in the specified schema, not the default public schema
func (suite *PostgresCustomSchemaTestSuite) TestCustomSchemaVerification() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("This test only applies to PostgreSQL")
		return
	}

	var schemaName string
	err := suite.DB.Raw("SELECT current_schema()").Scan(&schemaName).Error
	suite.Require().NoError(err, "Failed to query current schema")
	suite.T().Logf("Current schema: %s", schemaName)

	var tableSchema string
	err = suite.DB.Raw(`
		SELECT table_schema 
		FROM information_schema.tables 
		WHERE table_name = 'users' 
		AND table_schema NOT IN ('pg_catalog', 'information_schema')
		LIMIT 1
	`).Scan(&tableSchema).Error
	suite.Require().NoError(err, "Failed to query users table schema")
	suite.T().Logf("Users table schema: %s", tableSchema)

	if dbConfig.PostgresSchema != "" {
		suite.Equal(dbConfig.PostgresSchema, tableSchema, "Users table should be in custom schema")
		suite.Equal(dbConfig.PostgresSchema, schemaName, "Current schema should be custom schema")
	} else {
		suite.Equal("public", tableSchema, "Users table should be in public schema when no custom schema specified")
	}
}

// TestCustomSchemaDataOperations verifies that data operations work correctly in custom schema
func (suite *PostgresCustomSchemaTestSuite) TestCustomSchemaDataOperations() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("This test only applies to PostgreSQL")
		return
	}

	email := "custom-schema-test@example.com"

	var countBefore int64
	err := suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND instance_id = ?", email, suite.TestInstance).Scan(&countBefore).Error
	suite.Require().NoError(err)
	suite.Equal(int64(0), countBefore, "User should not exist before signup")

	requestBody := map[string]interface{}{
		"email":    email,
		"password": "MySecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	response.Print()

	suite.Require().Equal(200, response.ResponseRecorder.Code, "Signup should succeed")

	var countAfter int64
	err = suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND instance_id = ?", email, suite.TestInstance).Scan(&countAfter).Error
	suite.Require().NoError(err)
	suite.Equal(int64(1), countAfter, "User should exist after signup")

	var userID string
	err = suite.DB.Raw("SELECT id FROM users WHERE email = ? AND instance_id = ?", email, suite.TestInstance).Scan(&userID).Error
	suite.Require().NoError(err)
	suite.NotEmpty(userID, "User ID should not be empty")

	if dbConfig.PostgresSchema != "" {
		var schemaName string
		err = suite.DB.Raw(`
			SELECT table_schema 
			FROM information_schema.tables 
			WHERE table_name = 'users' 
			AND table_schema = ?
			LIMIT 1
		`, dbConfig.PostgresSchema).Scan(&schemaName).Error
		suite.Require().NoError(err)
		suite.Equal(dbConfig.PostgresSchema, schemaName, "Users table should be in custom schema")
	}
}

// TestCustomSchemaQueryAllTables verifies that all tables are created in the custom schema
func (suite *PostgresCustomSchemaTestSuite) TestCustomSchemaQueryAllTables() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.PostgresSchema == "" {
		suite.T().Skip("Skipping test: no custom schema configured")
		return
	}

	expectedTables := []string{
		"users",
		"sessions",
		"refresh_tokens",
		"identities",
		"mfa_factors",
		"mfa_challenges",
		"mfaamr_claims",
		"one_time_tokens",
		"flow_states",
		"saml_relay_states",
		"sso_providers",
		"saml_providers",
		"sso_instances",
		"auth_instances",
	}

	for _, tableName := range expectedTables {
		var count int64
		err := suite.DB.Raw(`
			SELECT COUNT(*) 
			FROM information_schema.tables 
			WHERE table_schema = ? 
			AND table_name = ?
		`, dbConfig.PostgresSchema, tableName).Scan(&count).Error
		suite.Require().NoError(err, "Failed to query table: %s", tableName)
		suite.Equal(int64(1), count, "Table %s should exist in custom schema %s", tableName, dbConfig.PostgresSchema)
	}
}

func TestPostgresCustomSchemaTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresCustomSchemaTestSuite))
}
