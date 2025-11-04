package tests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CrossSchemaQueryTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *CrossSchemaQueryTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestCrossSchemaJoin verifies that the main project can JOIN slauth tables across schemas
// This is the real-world usage scenario when slauth is embedded as a library
func (suite *CrossSchemaQueryTestSuite) TestCrossSchemaJoin() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("Cross-schema query test only applies to PostgreSQL")
		return
	}

	if dbConfig.PostgresSchema == "" {
		suite.T().Skip("No custom schema configured")
		return
	}

	// 1. Create main project's business table (in public schema)
	err := suite.DB.Exec(`
		CREATE TABLE IF NOT EXISTS public.app_orders (
			id SERIAL PRIMARY KEY,
			user_email VARCHAR(255) NOT NULL,
			product_name VARCHAR(255) NOT NULL,
			amount DECIMAL(10,2) NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`).Error
	suite.Require().NoError(err, "Failed to create app_orders table")

	// 2. slauth registers user (in custom schema)
	email := "cross-schema-user@example.com"
	requestBody := map[string]interface{}{
		"email":    email,
		"password": "SecurePassword2024!",
	}

	response := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", requestBody)
	suite.Require().Equal(200, response.ResponseRecorder.Code, "Signup should succeed")

	// 3. Main project creates order
	err = suite.DB.Exec(`
		INSERT INTO public.app_orders (user_email, product_name, amount)
		VALUES (?, 'Test Product', 99.99)
	`, email).Error
	suite.Require().NoError(err, "Failed to insert order")

	// 4. Main project executes cross-schema JOIN query
	type OrderWithUser struct {
		OrderID        int
		UserEmail      string
		ProductName    string
		Amount         float64
		AuthUserID     *string
		EmailConfirmed bool
	}

	var results []OrderWithUser
	err = suite.DB.Raw(fmt.Sprintf(`
		SELECT 
			o.id as order_id,
			o.user_email,
			o.product_name,
			o.amount,
			u.id::text as auth_user_id,
			CASE WHEN u.email_confirmed_at IS NOT NULL THEN true ELSE false END as email_confirmed
		FROM public.app_orders o
		LEFT JOIN %s.users u ON o.user_email = u.email
		WHERE o.user_email = ?
	`, dbConfig.PostgresSchema), email).Scan(&results).Error

	suite.Require().NoError(err, "Cross-schema JOIN should succeed")
	suite.Equal(1, len(results), "Should find one order")
	suite.NotNil(results[0].AuthUserID, "Should have auth user ID from JOIN")
	suite.T().Logf("Cross-schema JOIN result: OrderID=%d, UserEmail=%s, AuthUserID=%v, EmailConfirmed=%v",
		results[0].OrderID, results[0].UserEmail, *results[0].AuthUserID, results[0].EmailConfirmed)

	// 5. Cleanup
	suite.DB.Exec(`DROP TABLE IF EXISTS public.app_orders`)
}

// TestAggregateQuery verifies that the main project can query slauth statistics
func (suite *CrossSchemaQueryTestSuite) TestAggregateQuery() {
	dbConfig := suite.loadDatabaseConfig()
	if dbConfig.Type != "postgres" && dbConfig.Type != "postgresql" {
		suite.T().Skip("This test only applies to PostgreSQL")
		return
	}

	if dbConfig.PostgresSchema == "" {
		suite.T().Skip("No custom schema configured")
		return
	}

	// Main project queries authentication statistics
	type AuthStats struct {
		TotalUsers     int
		ConfirmedUsers int
		TodaySessions  int
	}

	var stats AuthStats
	err := suite.DB.Raw(fmt.Sprintf(`
		SELECT 
			COUNT(DISTINCT u.id) as total_users,
			COUNT(DISTINCT CASE WHEN u.email_confirmed_at IS NOT NULL THEN u.id END) as confirmed_users,
			COUNT(DISTINCT s.id) as today_sessions
		FROM %s.users u
		LEFT JOIN %s.sessions s ON s.user_id = u.id AND s.created_at::date = CURRENT_DATE
		WHERE u.instance_id = ?
	`, dbConfig.PostgresSchema, dbConfig.PostgresSchema), suite.TestInstance).Scan(&stats).Error

	suite.Require().NoError(err, "Aggregate query should succeed")
	suite.T().Logf("Auth stats: TotalUsers=%d, ConfirmedUsers=%d, TodaySessions=%d",
		stats.TotalUsers, stats.ConfirmedUsers, stats.TodaySessions)
}

func TestCrossSchemaQueryTestSuite(t *testing.T) {
	suite.Run(t, new(CrossSchemaQueryTestSuite))
}
