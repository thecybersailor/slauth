package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/flaboy/aira-core/pkg/aira"
	"github.com/flaboy/aira-core/pkg/config"
	"github.com/flaboy/envconf"
	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/auth"
	"github.com/thecybersailor/slauth/pkg/providers/captcha/cloudflare"
	"github.com/thecybersailor/slauth/pkg/providers/identidies/google"
	awssms "github.com/thecybersailor/slauth/pkg/providers/sms/aws"
)

type Config struct {
	Infra  config.InfraConfig `cfg:"SYS"`
	Listen string             `cfg:"LISTEN" default:":9001"`

	GoogleClientID     string `cfg:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `cfg:"GOOGLE_CLIENT_SECRET"`
}

var cfg *Config

func main() {
	cfg = &Config{}
	if err := envconf.Load(".env", cfg); err != nil {
		panic(err)
	}

	if err := aira.Start(&cfg.Infra); err != nil {
		panic(err)
	}

	if err := auth.Start(); err != nil {
		panic(err)
	}

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
				return aws.Endpoint{URL: "http://localhost:8026"}, nil
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

	userAuth := auth.NewService("user", globalJWTSecret, globalAppSecret).
		SetCaptchaProvider(cloudflare.NewCaptchaProvider("0x4AAAAAABeUh101CXnQ_8-z")).
		AddIdentityProvider(google.NewGoogleProvider(&google.GoogleOAuthConfig{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
		})).
		SetSMSProvider(smsProvider)

	// Add delay middleware to observe loading state
	r.Use(func(c *gin.Context) {
		time.Sleep(200 * time.Millisecond)
		c.Next()
	})

	// Public routes for authentication - following design document
	userAuth.HandleAuthRequest(r.Group("/auth"))   // http://example.com/auth
	userAuth.HandleAdminRequest(r.Group("/admin")) //http://example.com/admin

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
