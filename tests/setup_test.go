package tests

import (
	"fmt"
	"os"
	"testing"
	"time"

	coreconfig "github.com/flaboy/aira-core/pkg/config"
	"github.com/flaboy/aira-core/pkg/redis"
	"github.com/flaboy/envconf"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/controller"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/providers/mfa"
	"github.com/thecybersailor/slauth/pkg/registry"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type DatabaseConfig struct {
	Type     string `cfg:"SYS_DB_TYPE" default:"sqlite"`
	Host     string `cfg:"SYS_DB_HOST" default:"localhost"`
	Port     int    `cfg:"SYS_DB_PORT" default:"3306"`
	User     string `cfg:"SYS_DB_USER" default:""`
	Password string `cfg:"SYS_DB_PASSWORD" default:""`
	DBName   string `cfg:"SYS_DB_DBNAME" default:"test"`

	// PostgreSQL specific
	PostgresHost     string `cfg:"POSTGRES_HOST" default:"localhost"`
	PostgresUser     string `cfg:"POSTGRES_USER" default:"pguser"`
	PostgresDBName   string `cfg:"POSTGRES_DBNAME" default:"auth"`
	PostgresPassword string `cfg:"POSTGRES_PASSWORD" default:"passwd"`
	PostgresPort     int    `cfg:"POSTGRES_PORT" default:"5432"`
	PostgresSchema   string `cfg:"POSTGRES_SCHEMA" default:""`
}

type PostgresSchemaNameStrategy struct {
	schema.NamingStrategy
	Schema string
}

func (ps *PostgresSchemaNameStrategy) TableName(table string) string {
	tableName := ps.NamingStrategy.TableName(table)
	if ps.Schema != "" {
		return ps.Schema + "." + tableName
	}
	return tableName
}

type TestAdminRouteHandler struct {
	authService services.AuthService
}

func (h *TestAdminRouteHandler) SetAuthService(authService services.AuthService) {
	h.authService = authService
}

func (h *TestAdminRouteHandler) RegisterRoutes(router gin.IRouter) {
	controller.RegisterAdminRoutes(router, h.authService)
}

type TestSuite struct {
	suite.Suite
	DB            *gorm.DB
	Router        *gin.Engine
	AuthService   services.AuthService
	TestInstance  string
	EmailProvider *MockEmailProvider
	SMSProvider   *MockSMSProvider
}

func (suite *TestSuite) SetupSuite() {

	suite.TestInstance = fmt.Sprintf("test-%d.com", time.Now().UnixNano())

	suite.setupDatabase()
	suite.setupAuthService()
	suite.setupRouter()
}

func (suite *TestSuite) setupDatabase() {
	dbConfig := suite.loadDatabaseConfig()

	if dbConfig.Type == "postgres" || dbConfig.Type == "postgresql" {
		if dbConfig.PostgresSchema != "" {
			db, err := suite.connectDatabaseWithoutSchema(dbConfig)
			suite.Require().NoError(err)

			err = db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", dbConfig.PostgresSchema)).Error
			suite.Require().NoError(err, "Failed to create schema: %s", dbConfig.PostgresSchema)

			sqlDB, err := db.DB()
			suite.Require().NoError(err)
			sqlDB.Close()
		}
	}

	db, err := suite.connectDatabase(dbConfig)
	suite.Require().NoError(err)

	err = models.AutoMigrate(db)
	suite.Require().NoError(err)

	suite.DB = db
}

func (suite *TestSuite) loadDatabaseConfig() *DatabaseConfig {
	config := &DatabaseConfig{}

	confFile := os.Getenv("CONF_FILE")
	if confFile == "" {

		config.Type = "sqlite"
		return config
	}

	err := envconf.Load(confFile, config)
	suite.Require().NoError(err, "Failed to load config file: %s", confFile)

	return config
}

func (suite *TestSuite) connectDatabaseWithoutSchema(config *DatabaseConfig) (*gorm.DB, error) {
	if config.Type != "postgres" && config.Type != "postgresql" {
		return nil, fmt.Errorf("connectDatabaseWithoutSchema only supports PostgreSQL")
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=UTC",
		config.PostgresHost, config.PostgresUser, config.PostgresPassword,
		config.PostgresDBName, config.PostgresPort)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

func (suite *TestSuite) connectDatabase(config *DatabaseConfig) (*gorm.DB, error) {
	switch config.Type {
	case "mysql":
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=UTC",
			config.User, config.Password, config.Host, config.Port, config.DBName)
		return gorm.Open(mysql.Open(dsn), &gorm.Config{})

	case "postgres", "postgresql":
		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=UTC",
			config.PostgresHost, config.PostgresUser, config.PostgresPassword,
			config.PostgresDBName, config.PostgresPort)

		gormConfig := &gorm.Config{}
		if config.PostgresSchema != "" {
			gormConfig.NamingStrategy = &PostgresSchemaNameStrategy{
				Schema: config.PostgresSchema,
			}
		}

		db, err := gorm.Open(postgres.Open(dsn), gormConfig)
		if err != nil {
			return nil, err
		}

		if config.PostgresSchema != "" {
			sqlDB, err := db.DB()
			if err != nil {
				return nil, err
			}
			_, err = sqlDB.Exec(fmt.Sprintf("SET search_path TO %s", config.PostgresSchema))
			if err != nil {
				return nil, fmt.Errorf("failed to set search_path: %w", err)
			}
		}
		return db, nil

	case "sqlite", "":

		return gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})

	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

func (suite *TestSuite) setupAuthService() {

	coreconfig.Config = &coreconfig.InfraConfig{
		RedisAddr:     "localhost:6379",
		RedisPassword: "",
		RedisDB:       0,
	}

	if err := redis.InitRedis(); err != nil {
		suite.Require().NoError(err, "Failed to initialize Redis")
	}

	suite.EmailProvider = NewMockEmailProvider()
	suite.SMSProvider = NewMockSMSProvider()

	// Generate test keys for JWT signing
	testSecrets, err := GenerateTestSecrets(types.SignAlgES256)
	suite.Require().NoError(err, "Failed to generate test keys")

	// Create static secrets provider for testing
	secretsProvider := services.NewStaticSecretsProvider(testSecrets)

	suite.AuthService, _ = registry.GetOrCreateAuthService(suite.TestInstance, secretsProvider, suite.DB)
	suite.AuthService.SetEmailProvider(suite.EmailProvider).
		SetSMSProvider(suite.SMSProvider).
		AddMFAProvider(mfa.NewTOTPProvider()).
		RegisterMessageTemplateResolver(services.NewFileTemplateResolver("../templates")).
		SetAdminRouteHandler(&TestAdminRouteHandler{})
}

func (suite *TestSuite) setupRouter() {
	suite.Router = gin.New()

	authGroup := suite.Router.Group("/auth")
	controller.RegisterRoutes(authGroup, suite.AuthService)

	adminGroup := suite.Router.Group("/admin")
	suite.AuthService.HandleAdminRequest(adminGroup)
}

func TestTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
