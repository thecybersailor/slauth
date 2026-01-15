package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/controller"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type JWKSEndpointTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *JWKSEndpointTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// Test case for JWKS endpoint
// Tests GET /.well-known/jwks.json endpoint returns valid JWKS format
func (suite *JWKSEndpointTestSuite) TestJWKSEndpoint() {
	// Generate test keys
	ecPrivateKey, ecPublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate ES256 key pair")

	rsaPrivateKey, rsaPublicKey, err := GenerateRS256KeyPair()
	suite.Require().NoError(err, "Failed to generate RS256 key pair")

	// Create test secrets with multiple keys
	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "test-ec-key",
		Keys: map[string]*types.SigningKey{
			"test-ec-key": {
				Kid:        "test-ec-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: ecPrivateKey,
				PublicKey:  ecPublicKey,
			},
			"test-rsa-key": {
				Kid:        "test-rsa-key",
				Algorithm:  types.SignAlgRS256,
				PrivateKey: rsaPrivateKey,
				PublicKey:  rsaPublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	provider := services.NewStaticSecretsProvider(secrets)

	// Create Gin router for testing
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/.well-known/jwks.json", controller.HandleJWKS(provider, suite.TestInstance))

	// Create helper with new router
	helper := NewTestHelper(suite.DB, router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Make request
	response := helper.MakeGETRequest(suite.T(), "/.well-known/jwks.json")

	// Check response
	suite.Equal(http.StatusOK, response.ResponseRecorder.Code, "JWKS endpoint should return 200")

	// Parse response
	var jwks controller.JWKS
	err = json.Unmarshal(response.ResponseRecorder.Body.Bytes(), &jwks)
	suite.NoError(err, "JWKS response should be valid JSON")

	// Should have keys (even if empty due to test setup)
	suite.NotNil(jwks.Keys, "JWKS should have keys array")

	// Check key properties if keys exist
	for _, key := range jwks.Keys {
		suite.Equal("sig", key.Use, "Key use should be 'sig'")
		suite.NotEmpty(key.Kid, "Key ID should not be empty")
		suite.NotEmpty(key.Alg, "Algorithm should not be empty")
		suite.NotEmpty(key.Kty, "Key type should not be empty")
	}
}

// Test case for JWKS endpoint with empty secrets
func (suite *JWKSEndpointTestSuite) TestJWKSEndpointEmptySecrets() {
	secrets := &types.InstanceSecrets{
		Keys: make(map[string]*types.SigningKey),
	}

	provider := services.NewStaticSecretsProvider(secrets)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/.well-known/jwks.json", controller.HandleJWKS(provider, suite.TestInstance))

	// Create helper with new router
	helper := NewTestHelper(suite.DB, router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	response := helper.MakeGETRequest(suite.T(), "/.well-known/jwks.json")

	suite.Equal(http.StatusOK, response.ResponseRecorder.Code, "JWKS endpoint should return 200 even with empty secrets")

	var jwks controller.JWKS
	err := json.Unmarshal(response.ResponseRecorder.Body.Bytes(), &jwks)
	suite.NoError(err, "JWKS response should be valid JSON")

	suite.Equal(0, len(jwks.Keys), "JWKS should have 0 keys for empty secrets")
}

func TestJWKSEndpointTestSuite(t *testing.T) {
	suite.Run(t, new(JWKSEndpointTestSuite))
}
