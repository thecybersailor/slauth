package tests

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// TableStructureTestSuite tests that table names match expected prefix/schema
type TableStructureTestSuite struct {
	TestSuite
}

func TestTableStructureTestSuite(t *testing.T) {
	suite.Run(t, new(TableStructureTestSuite))
}

// TestTableStructureMatchesExpected verifies that all expected tables exist with correct names
func (suite *TableStructureTestSuite) TestTableStructureMatchesExpected() {
	tablePrefix := os.Getenv("TABLE_PREFIX")
	if tablePrefix == "" {
		suite.T().Skip("TABLE_PREFIX not set, skipping table structure test")
		return
	}

	// Expected base table names (14 tables from AllModels)
	expectedBaseTables := []string{
		"users",
		"identities",
		"sessions",
		"refresh_tokens",
		"mfa_factors",
		"mfa_challenges",
		"mfa_amr_claims",
		"one_time_tokens",
		"flow_states",
		"saml_relay_states",
		"sso_providers",
		"saml_providers",
		"sso_instances",
		"auth_instances",
	}

	// Build expected table names with prefix
	expectedTables := make(map[string]bool)
	for _, baseTable := range expectedBaseTables {
		fullTableName := tablePrefix + baseTable
		expectedTables[fullTableName] = true
	}

	// Get actual table names from database
	actualTables, err := suite.getActualTableNames()
	suite.Require().NoError(err, "Failed to get actual table names")

	// Convert to map for easy comparison
	actualTableMap := make(map[string]bool)
	for _, table := range actualTables {
		actualTableMap[table] = true
	}

	// Verify all expected tables exist
	for expectedTable := range expectedTables {
		suite.True(actualTableMap[expectedTable],
			"Expected table '%s' not found in database", expectedTable)
	}

	// Verify no unexpected business tables exist
	// For SQLite, we allow system tables like sqlite_sequence
	// For MySQL/PostgreSQL, we check that all tables match expected set
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type == "sqlite" || dbConfig.Type == "" {
		// For SQLite, only verify that expected tables exist
		// System tables are allowed
		suite.T().Logf("SQLite: Found %d tables, verified %d expected tables exist",
			len(actualTables), len(expectedTables))
	} else {
		// For MySQL/PostgreSQL, verify exact match (allowing only expected tables)
		// Filter out system tables if any
		businessTables := suite.filterBusinessTables(actualTables, tablePrefix)
		suite.Equal(len(expectedTables), len(businessTables),
			"Number of business tables should match expected count")
		for actualTable := range businessTables {
			suite.True(expectedTables[actualTable],
				"Unexpected business table found: '%s'", actualTable)
		}
	}
}

// getActualTableNames queries the database for actual table names
func (suite *TableStructureTestSuite) getActualTableNames() ([]string, error) {
	dbConfig := suite.loadDatabaseConfig()
	tablePrefix := os.Getenv("TABLE_PREFIX")

	switch dbConfig.Type {
	case "sqlite", "":
		return suite.getSQLiteTableNames()
	case "mysql":
		return suite.getMySQLTableNames(dbConfig.DBName)
	case "postgres", "postgresql":
		return suite.getPostgreSQLTableNames(tablePrefix)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbConfig.Type)
	}
}

// getSQLiteTableNames queries sqlite_master for table names
func (suite *TableStructureTestSuite) getSQLiteTableNames() ([]string, error) {
	var tables []string
	err := suite.DB.Raw(`
		SELECT name FROM sqlite_master 
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
	`).Scan(&tables).Error
	return tables, err
}

// getMySQLTableNames queries information_schema for table names
func (suite *TableStructureTestSuite) getMySQLTableNames(dbName string) ([]string, error) {
	var tables []string
	err := suite.DB.Raw(`
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = ?
	`, dbName).Scan(&tables).Error
	return tables, err
}

// getPostgreSQLTableNames queries information_schema for table names
// If prefix ends with ".", it queries the specific schema, otherwise queries public schema
func (suite *TableStructureTestSuite) getPostgreSQLTableNames(tablePrefix string) ([]string, error) {
	var schemaName string
	if strings.HasSuffix(tablePrefix, ".") {
		schemaName = strings.TrimSuffix(tablePrefix, ".")
	} else {
		schemaName = "public"
	}

	var tables []string
	err := suite.DB.Raw(`
		SELECT table_name 
		FROM information_schema.tables 
		WHERE table_schema = ?
	`, schemaName).Scan(&tables).Error
	return tables, err
}

// filterBusinessTables filters out system tables, keeping only tables with the expected prefix
func (suite *TableStructureTestSuite) filterBusinessTables(tables []string, tablePrefix string) map[string]bool {
	businessTables := make(map[string]bool)
	for _, table := range tables {
		// Include tables that start with the prefix
		if strings.HasPrefix(table, tablePrefix) {
			businessTables[table] = true
		}
	}
	return businessTables
}
