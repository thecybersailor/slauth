package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/flaboy/aira-core/pkg/config"
	"github.com/flaboy/aira-core/pkg/mailer"
	"github.com/flaboy/aira-core/pkg/redis"
	"github.com/flaboy/envconf"
	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/auth"
	"github.com/thecybersailor/slauth/pkg/controller"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/providers/captcha/cloudflare"
	"github.com/thecybersailor/slauth/pkg/providers/identidies/google"
	awssms "github.com/thecybersailor/slauth/pkg/providers/sms/aws"
	"github.com/thecybersailor/slauth/pkg/registry"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Config struct {
	Infra  config.InfraConfig `cfg:"SYS"`
	Listen string             `cfg:"LISTEN" default:":9001"`

	GoogleClientID     string `cfg:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `cfg:"GOOGLE_CLIENT_SECRET"`
	AWSSNSEndpoint     string `cfg:"AWS_SNS_ENDPOINT" default:"http://localhost:8026"`

	AuthServiceBaseUrl string `cfg:"AUTH_SERVICE_BASE_URL" default:"http://localhost:5180/auth"`
	SiteURL            string `cfg:"SITE_URL" default:"http://localhost:5180"`
}

var cfg *Config

func main() {
	gin.SetMode(gin.ReleaseMode)
	// Parse command line flags
	configFile := flag.String("c", ".env", "Configuration file path")
	flag.Parse()

	cfg = &Config{}
	if err := envconf.Load(*configFile, cfg); err != nil {
		panic(err)
	}

	// Print configuration
	fmt.Println("=== Configuration ===")
	fmt.Printf("Listen: %s\n", cfg.Listen)
	fmt.Printf("Database Type: %s\n", cfg.Infra.DB_TYPE)
	if cfg.Infra.DB_TYPE == "pgsql" {
		fmt.Printf("Database: PostgreSQL %s:%d/%s\n", cfg.Infra.DB_HOST, cfg.Infra.DB_PORT, cfg.Infra.DB_DBNAME)
	} else {
		fmt.Printf("Database: SQLite :memory:\n")
	}
	fmt.Printf("Redis: %s (DB: %d)\n", cfg.Infra.RedisAddr, cfg.Infra.RedisDB)
	fmt.Printf("SMTP: %s:%d (From: %s)\n", cfg.Infra.SendMail.Host, cfg.Infra.SendMail.Port, cfg.Infra.SendMail.From)
	fmt.Printf("AWS SNS Endpoint: %s\n", cfg.AWSSNSEndpoint)
	fmt.Printf("Auth Service Base URL: %s\n", cfg.AuthServiceBaseUrl)
	fmt.Printf("Site URL: %s\n", cfg.SiteURL)
	fmt.Println("====================")

	// Initialize database
	var db *gorm.DB
	var err error

	if cfg.Infra.DB_TYPE == "pgsql" {
		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
			cfg.Infra.DB_HOST, cfg.Infra.DB_USER, cfg.Infra.DB_PASSWORD, cfg.Infra.DB_DBNAME, cfg.Infra.DB_PORT)
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			panic(fmt.Sprintf("Failed to connect PostgreSQL: %v", err))
		}
	} else {
		db, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		if err != nil {
			panic(fmt.Sprintf("Failed to connect SQLite: %v", err))
		}
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		panic(fmt.Sprintf("Failed to get underlying sql.DB: %v", err))
	}

	if cfg.Infra.DB_TYPE == "pgsql" {
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(5)
	} else {
		// Critical: Set MaxOpenConns to 1 for memory database to prevent table loss
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Set global DB for models package
	models.DB = db

	if err := models.AutoMigrate(db); err != nil {
		panic(fmt.Sprintf("Failed to migrate database: %v", err))
	}

	// Initialize Redis and SMTP
	config.Config = &cfg.Infra
	if err := redis.InitRedis(); err != nil {
		panic(fmt.Sprintf("Failed to initialize Redis: %v", err))
	}

	// Initialize SMTP mailer
	mailer.InitSMTP()

	// Create Gin engine
	r := gin.Default()

	// Set pin error handler
	pin.SetErrorHandler(func(c *gin.Context, err error) error {
		fmt.Println("Error:", err)
		return nil
	})

	// Create AWS SMS provider
	awsConfig, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     "dummy-access-key",
				SecretAccessKey: "dummy-secret-key",
			}, nil
		})),
		awsconfig.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if service == "SNS" {
				return aws.Endpoint{URL: cfg.AWSSNSEndpoint}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	smsProvider := awssms.NewAWSSMSProvider(awsConfig)

	// Load global secrets from environment variables, dynamic config loaded from database
	globalJWTSecret := "your-global-jwt-secret-change-in-production"
	globalAppSecret := "your-global-app-secret-change-in-production"

	// Register auth service with database
	userAuth := registry.RegisterAuthService("user", globalJWTSecret, globalAppSecret, db)

	// Set route handlers
	userAuth.SetRouteHandler(&auth.ControllerRouteHandler{})
	userAuth.SetAdminRouteHandler(&auth.AdminRouteHandler{})

	// Configure providers
	userAuth.SetCaptchaProvider(cloudflare.NewCaptchaProvider("0x4AAAAAABeUh101CXnQ_8-z")).
		AddIdentityProvider(google.NewGoogleProvider(&google.GoogleOAuthConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
		})).
		SetSMSProvider(smsProvider)

	// Update config and save to database
	serviceConfig := userAuth.GetConfig()
	serviceConfig.AuthServiceBaseUrl = cfg.AuthServiceBaseUrl
	serviceConfig.SiteURL = cfg.SiteURL
	userAuth.SaveConfig(serviceConfig)

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "timestamp": "2025-10-01 17:44:36", "hot_reload": "working"})
	})

	// Add delay middleware to observe loading state
	r.Use(func(c *gin.Context) {
		time.Sleep(200 * time.Millisecond)
		c.Next()
	})

	// Public routes for authentication - following design document
	authGroup := r.Group("/auth")
	controller.RegisterRoutes(authGroup, userAuth)

	adminGroup := r.Group("/admin")
	userAuth.HandleAdminRequest(adminGroup)

	// Start server
	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	fmt.Println("Server starting on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// Test comment for air reload
