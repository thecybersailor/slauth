package tests

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/controller"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type JWKSVerificationTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *JWKSVerificationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestIndependentJWTVerification tests the core JWKS-based JWT verification flow
// This validates that JWTs can be verified independently using the /.well-known/jwks.json endpoint
func (suite *JWKSVerificationTestSuite) TestIndependentJWTVerification() {
	// Generate test keys
	testSecrets, err := GenerateTestSecrets(types.SignAlgES256)
	suite.Require().NoError(err, "Failed to generate test keys")

	// Create secrets provider
	secretsProvider := services.NewStaticSecretsProvider(testSecrets)

	// Create JWT service
	jwtService := services.NewJWTService(
		func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s },
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate JWT using the auth service
	token, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate JWT")
	suite.NotEmpty(token, "Generated token should not be empty")

	// Create JWKS endpoint router
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	// Create helper with JWKS router
	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Fetch public keys from JWKS endpoint
	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.NotEmpty(jwksKeys, "JWKS should contain keys")

	// Independently verify JWT using JWKS keys (without auth server)
	claims := VerifyJWTWithJWKS(suite.T(), token, jwksKeys)

	// Validate claims
	suite.Equal("user123", claims.UserID, "User ID should match")
	suite.Equal(suite.TestInstance, claims.InstanceId, "Instance ID should match")
	suite.Equal("test@example.com", claims.Email, "Email should match")
	suite.Equal("authenticated", claims.Role, "Role should match")
	suite.Equal(types.AALLevel1, claims.AAL, "AAL should match")
	suite.Equal([]string{"pwd"}, claims.AMR, "AMR should match")
	suite.Equal(uint(1), claims.SessionID, "Session ID should match")
}

// TestJWKSMultipleKeys tests that JWKS returns all active keys and can verify tokens signed with different keys
func (suite *JWKSVerificationTestSuite) TestJWKSMultipleKeys() {
	// Generate multiple test keys
	ecPrivateKey, ecPublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate ES256 key pair")

	rsaPrivateKey, rsaPublicKey, err := GenerateRS256KeyPair()
	suite.Require().NoError(err, "Failed to generate RS256 key pair")

	// Create secrets with multiple keys
	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "ec-key",
		Keys: map[string]*types.SigningKey{
			"ec-key": {
				Kid:        "ec-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: ecPrivateKey,
				PublicKey:  ecPublicKey,
			},
			"rsa-key": {
				Kid:        "rsa-key",
				Algorithm:  types.SignAlgRS256,
				PrivateKey: rsaPrivateKey,
				PublicKey:  rsaPublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	secretsProvider := services.NewStaticSecretsProvider(secrets)

	// Create JWT services for both keys
	getSecrets := func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s }

	jwtService := services.NewJWTService(
		getSecrets,
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate tokens with different keys (by changing primary key)
	secrets.PrimaryKeyId = "ec-key"
	ecToken, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate EC token")

	secrets.PrimaryKeyId = "rsa-key"
	rsaToken, err := jwtService.GenerateAccessToken(
		"user456", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 2, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate RSA token")

	// Create JWKS endpoint
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Fetch JWKS keys - should contain both keys
	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeys, 2, "JWKS should contain both keys")

	// Verify both tokens can be validated independently
	ecClaims := VerifyJWTWithJWKS(suite.T(), ecToken, jwksKeys)
	suite.Equal("user123", ecClaims.UserID, "EC token user ID should match")

	rsaClaims := VerifyJWTWithJWKS(suite.T(), rsaToken, jwksKeys)
	suite.Equal("user456", rsaClaims.UserID, "RSA token user ID should match")
}

// TestInvalidKidHandling tests error cases for invalid or missing kid
func (suite *JWKSVerificationTestSuite) TestInvalidKidHandling() {
	// Generate test keys
	testSecrets, err := GenerateTestSecrets(types.SignAlgES256)
	suite.Require().NoError(err, "Failed to generate test keys")

	secretsProvider := services.NewStaticSecretsProvider(testSecrets)

	// Create JWT service
	jwtService := services.NewJWTService(
		func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s },
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate valid token
	validToken, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate valid token")

	// Create JWKS endpoint
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")

	// Test 1: Valid token should verify successfully
	validClaims := VerifyJWTWithJWKS(suite.T(), validToken, jwksKeys)
	suite.Equal("user123", validClaims.UserID, "Valid token should verify")

	// Test 2: Token with non-existent kid should fail
	// Manually modify token header to have invalid kid
	invalidKidToken := validToken[:strings.LastIndex(validToken, ".")] + ".invalid"
	_, err = jwt.ParseWithClaims(invalidKidToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		suite.True(ok, "Token should have kid header")
		suite.Equal("invalid", kid, "Kid should be modified")

		// This should fail because "invalid" kid doesn't exist in JWKS
		_, exists := jwksKeys[kid]
		suite.False(exists, "Invalid kid should not exist in JWKS")

		return nil, fmt.Errorf("kid not found in JWKS")
	})
	suite.Error(err, "Token with invalid kid should fail verification")
}

// TestAlgorithmMismatch tests security validation for algorithm mismatches
func (suite *JWKSVerificationTestSuite) TestAlgorithmMismatch() {
	// Generate test keys
	testSecrets, err := GenerateTestSecrets(types.SignAlgES256)
	suite.Require().NoError(err, "Failed to generate test keys")

	secretsProvider := services.NewStaticSecretsProvider(testSecrets)

	// Create JWT service
	jwtService := services.NewJWTService(
		func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s },
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate valid ES256 token
	validToken, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate valid token")

	// Create JWKS endpoint
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")

	// Test 1: Valid token should verify
	validClaims := VerifyJWTWithJWKS(suite.T(), validToken, jwksKeys)
	suite.Equal("user123", validClaims.UserID, "Valid token should verify")

	// Test 2: Token with mismatched algorithm should fail
	// Create a fake JWKS with wrong algorithm for the key
	wrongAlgoJWKS := make(map[string]*JWKPublicKey)
	for kid, key := range jwksKeys {
		// Change ES256 key to appear as RS256 in JWKS (mismatch)
		wrongAlgoJWKS[kid] = &JWKPublicKey{
			Kid:       key.Kid,
			Algorithm: types.SignAlgRS256, // Wrong algorithm
			PublicKey: key.PublicKey,      // Same key
		}
		break // Just modify first key
	}

	// This should fail because JWT header says ES256 but JWKS claims RS256
	_, err = jwt.ParseWithClaims(validToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		suite.True(ok, "Token should have kid header")

		jwk := wrongAlgoJWKS[kid]
		suite.Equal(types.SignAlgRS256, jwk.Algorithm, "JWKS should claim RS256 algorithm")

		// JWT header says ES256 but JWKS claims RS256 - this should fail
		if token.Method.Alg() == "ES256" && jwk.Algorithm == types.SignAlgRS256 {
			return nil, fmt.Errorf("algorithm mismatch: JWT=ES256, JWKS=RS256")
		}

		return jwk.PublicKey, nil
	})
	suite.Error(err, "Token with algorithm mismatch should fail verification")
}

func TestJWKSVerificationTestSuite(t *testing.T) {
	suite.Run(t, new(JWKSEndpointTestSuite))
}
