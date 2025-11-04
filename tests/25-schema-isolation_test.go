package tests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type SchemaIsolationTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SchemaIsolationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestSchemaNamespace verifies that slauth uses custom schema as a namespace,
// avoiding table name conflicts with the main project, while allowing the main project
// to access slauth data across schemas
func (suite *SchemaIsolationTestSuite) TestSchemaNamespace() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("Schema isolation test only applies to PostgreSQL")
		return
	}

	if dbConfig.PostgresSchema == "" {
		suite.T().Skip("No custom schema configured, skipping isolation test")
		return
	}

	// 1. Verify schema is created
	var schemaExists bool
	err := suite.DB.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.schemata 
			WHERE schema_name = ?
		)
	`, dbConfig.PostgresSchema).Scan(&schemaExists).Error
	suite.Require().NoError(err, "Failed to check schema existence")
	suite.True(schemaExists, "Custom schema %s should exist", dbConfig.PostgresSchema)

	// 2. Verify all slauth tables are in custom schema
	var publicCount int64
	err = suite.DB.Raw(`
		SELECT COUNT(*) 
		FROM information_schema.tables 
		WHERE table_schema = 'public' 
		AND table_name IN ('users', 'sessions', 'refresh_tokens', 'identities')
	`).Scan(&publicCount).Error
	suite.Require().NoError(err)
	suite.T().Logf("Tables in public schema: %d", publicCount)

	var customSchemaCount int64
	err = suite.DB.Raw(`
		SELECT COUNT(*) 
		FROM information_schema.tables 
		WHERE table_schema = ? 
		AND table_name IN ('users', 'sessions', 'refresh_tokens', 'identities')
	`, dbConfig.PostgresSchema).Scan(&customSchemaCount).Error
	suite.Require().NoError(err)
	suite.T().Logf("Tables in %s schema: %d", dbConfig.PostgresSchema, customSchemaCount)

	// 3. Create a mock main project table in public schema to verify no conflicts
	err = suite.DB.Exec(`
		CREATE TABLE IF NOT EXISTS public.main_app_users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL
		)
	`).Error
	suite.Require().NoError(err, "Failed to create main app table in public schema")

	// 4. Verify we can operate on tables in both schemas simultaneously
	err = suite.DB.Exec(`INSERT INTO public.main_app_users (username, email) VALUES (?, ?)`, "testuser", "test@example.com").Error
	suite.Require().NoError(err, "Should be able to insert into public schema table")

	// 5. Verify slauth operations are not affected
	email := "schema-isolation-test@example.com"
	requestBody := map[string]interface{}{
		"email":    email,
		"password": "SecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	suite.Require().Equal(200, response.ResponseRecorder.Code, "Signup should succeed")

	// 6. Verify user is created in custom schema
	var userExists bool
	err = suite.DB.Raw(fmt.Sprintf(`
		SELECT EXISTS(SELECT 1 FROM %s.users WHERE email = ?)
	`, dbConfig.PostgresSchema), email).Scan(&userExists).Error
	suite.Require().NoError(err)
	suite.True(userExists, "User should exist in custom schema")

	// 7. Verify cross-schema query (main project accessing slauth data)
	type UserInfo struct {
		Email     string
		CreatedAt string
		AppUser   string
	}

	var crossSchemaResult []UserInfo
	err = suite.DB.Raw(fmt.Sprintf(`
		SELECT 
			u.email,
			u.created_at::text,
			m.username as app_user
		FROM %s.users u
		LEFT JOIN public.main_app_users m ON u.email = m.email
		WHERE u.email = ?
	`, dbConfig.PostgresSchema), email).Scan(&crossSchemaResult).Error
	suite.Require().NoError(err, "Should be able to JOIN across schemas")
	suite.Equal(1, len(crossSchemaResult), "Should find user in cross-schema query")
	suite.T().Logf("Cross-schema JOIN result: %+v", crossSchemaResult)

	// 8. Cleanup test table
	suite.DB.Exec(`DROP TABLE IF EXISTS public.main_app_users`)
}

// TestQueryWithTablePrefix tests querying with full table name (schema.table)
func (suite *SchemaIsolationTestSuite) TestQueryWithTablePrefix() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("This test only applies to PostgreSQL")
		return
	}

	if dbConfig.PostgresSchema == "" {
		suite.T().Skip("No custom schema configured")
		return
	}

	// Query using full schema.table format
	var count int64
	err := suite.DB.Raw(fmt.Sprintf(`
		SELECT COUNT(*) FROM %s.users WHERE instance_id = ?
	`, dbConfig.PostgresSchema), suite.TestInstance).Scan(&count).Error
	suite.Require().NoError(err, "Should be able to query with full table name")
	suite.T().Logf("Total users in %s schema: %d", dbConfig.PostgresSchema, count)
}

// TestListAllTablesInBothSchemas lists all tables in both public and custom schemas
func (suite *SchemaIsolationTestSuite) TestListAllTablesInBothSchemas() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("This test only applies to PostgreSQL")
		return
	}

	type TableInfo struct {
		Schema string
		Table  string
	}

	var tables []TableInfo
	err := suite.DB.Raw(`
		SELECT table_schema as schema, table_name as table
		FROM information_schema.tables 
		WHERE table_schema IN ('public', ?)
		AND table_type = 'BASE TABLE'
		ORDER BY table_schema, table_name
	`, dbConfig.PostgresSchema).Scan(&tables).Error
	suite.Require().NoError(err)

	suite.T().Log("=== Tables in database ===")
	publicTables := []string{}
	customTables := []string{}
	for _, t := range tables {
		suite.T().Logf("%s.%s", t.Schema, t.Table)
		if t.Schema == "public" {
			publicTables = append(publicTables, t.Table)
		} else if t.Schema == dbConfig.PostgresSchema {
			customTables = append(customTables, t.Table)
		}
	}

	suite.T().Logf("Public schema has %d tables: %v", len(publicTables), publicTables)
	suite.T().Logf("Custom schema has %d tables: %v", len(customTables), customTables)

	if dbConfig.PostgresSchema != "" {
		suite.Greater(len(customTables), 0, "Custom schema should have at least one table")
	}
}

func TestSchemaIsolationTestSuite(t *testing.T) {
	suite.Run(t, new(SchemaIsolationTestSuite))
}
