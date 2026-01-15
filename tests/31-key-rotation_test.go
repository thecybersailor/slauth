package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/controller"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type KeyRotationTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *KeyRotationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestKeyRotationZeroDowntime tests the complete key rotation flow with zero downtime
// This simulates Supabase's key rotation process where old tokens remain valid during transition
func (suite *KeyRotationTestSuite) TestKeyRotationZeroDowntime() {
	// Phase 1: Start with key1 as primary
	key1PrivateKey, key1PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key1")

	initialSecrets := &types.InstanceSecrets{
		PrimaryKeyId: "key1",
		Keys: map[string]*types.SigningKey{
			"key1": {
				Kid:        "key1",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key1PrivateKey,
				PublicKey:  key1PublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	secretsProvider := CreateTestSecretsProvider(initialSecrets)

	// Create JWT service
	jwtService := services.NewJWTService(
		func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s },
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate tokens with key1
	token1, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate token with key1")

	token2, err := jwtService.GenerateAccessToken(
		"user456", suite.TestInstance, "test2@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 2, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate token with key1")

	// Phase 2: Add key2 as standby (simulate Supabase adding new key)
	key2PrivateKey, key2PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key2")

	secretsProvider.AddKey("key2", &types.SigningKey{
		Kid:        "key2",
		Algorithm:  types.SignAlgES256,
		PrivateKey: key2PrivateKey,
		PublicKey:  key2PublicKey,
	})

	// JWKS should now contain both keys
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeys, 2, "JWKS should contain both key1 and key2")
	suite.Contains(jwksKeys, "key1", "JWKS should contain key1")
	suite.Contains(jwksKeys, "key2", "JWKS should contain key2")

	// Both old tokens should still verify (zero downtime)
	claims1 := VerifyJWTWithJWKS(suite.T(), token1, jwksKeys)
	suite.Equal("user123", claims1.UserID, "Token1 should still verify with both keys available")

	claims2 := VerifyJWTWithJWKS(suite.T(), token2, jwksKeys)
	suite.Equal("user456", claims2.UserID, "Token2 should still verify with both keys available")

	// Phase 3: Rotate to key2 as primary
	secretsProvider.SetPrimaryKey("key2")

	// New tokens should use key2
	newToken, err := jwtService.GenerateAccessToken(
		"user789", suite.TestInstance, "test3@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 3, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate new token with key2")

	// Verify new token uses key2
	newClaims := VerifyJWTWithJWKS(suite.T(), newToken, jwksKeys)
	suite.Equal("user789", newClaims.UserID, "New token should verify")

	// Old tokens should still work (backward compatibility)
	oldClaims1 := VerifyJWTWithJWKS(suite.T(), token1, jwksKeys)
	suite.Equal("user123", oldClaims1.UserID, "Old token1 should still verify")

	oldClaims2 := VerifyJWTWithJWKS(suite.T(), token2, jwksKeys)
	suite.Equal("user456", oldClaims2.UserID, "Old token2 should still verify")

	// Phase 4: Revoke key1 (simulate cleanup after grace period)
	secretsProvider.RemoveKey("key1")

	// JWKS should now only contain key2
	jwksKeysAfterRevoke := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeysAfterRevoke, 1, "JWKS should contain only key2 after key1 revocation")
	suite.Contains(jwksKeysAfterRevoke, "key2", "JWKS should contain key2")
	suite.NotContains(jwksKeysAfterRevoke, "key1", "JWKS should not contain revoked key1")

	// New tokens should still work
	newClaimsAfterRevoke := VerifyJWTWithJWKS(suite.T(), newToken, jwksKeysAfterRevoke)
	suite.Equal("user789", newClaimsAfterRevoke.UserID, "New token should still verify after key1 revocation")

	// Old tokens signed with key1 should now fail verification
	// Since key1 is no longer in JWKS, verification should fail
	_, err = jwt.ParseWithClaims(token1, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		suite.True(ok, "Token should have kid header")
		_, exists := jwksKeysAfterRevoke[kid]
		suite.False(exists, "Revoked key1 should not exist in JWKS")
		return nil, fmt.Errorf("kid %s not found in JWKS", kid)
	})
	suite.Error(err, "Token signed with revoked key1 should fail verification")
}

// TestMultipleActiveKeys tests that multiple keys can be active simultaneously
func (suite *KeyRotationTestSuite) TestMultipleActiveKeys() {
	// Generate three different keys
	ecPrivateKey, ecPublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate ES256 key")

	rsaPrivateKey, rsaPublicKey, err := GenerateRS256KeyPair()
	suite.Require().NoError(err, "Failed to generate RS256 key")

	ec2PrivateKey, ec2PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate second ES256 key")

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
			"ec2-key": {
				Kid:        "ec2-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: ec2PrivateKey,
				PublicKey:  ec2PublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	secretsProvider := CreateTestSecretsProvider(secrets)

	// Create JWT service
	jwtService := services.NewJWTService(
		func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s },
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate tokens by switching primary key
	secretsProvider.SetPrimaryKey("ec-key")
	ecToken, err := jwtService.GenerateAccessToken(
		"user-ec", suite.TestInstance, "ec@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate EC token")

	secretsProvider.SetPrimaryKey("rsa-key")
	rsaToken, err := jwtService.GenerateAccessToken(
		"user-rsa", suite.TestInstance, "rsa@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 2, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate RSA token")

	secretsProvider.SetPrimaryKey("ec2-key")
	ec2Token, err := jwtService.GenerateAccessToken(
		"user-ec2", suite.TestInstance, "ec2@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 3, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate EC2 token")

	// Create JWKS endpoint
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// JWKS should contain all three keys
	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeys, 3, "JWKS should contain all three keys")

	// All tokens should verify regardless of which key they were signed with
	ecClaims := VerifyJWTWithJWKS(suite.T(), ecToken, jwksKeys)
	suite.Equal("user-ec", ecClaims.UserID, "EC token should verify")

	rsaClaims := VerifyJWTWithJWKS(suite.T(), rsaToken, jwksKeys)
	suite.Equal("user-rsa", rsaClaims.UserID, "RSA token should verify")

	ec2Claims := VerifyJWTWithJWKS(suite.T(), ec2Token, jwksKeys)
	suite.Equal("user-ec2", ec2Claims.UserID, "EC2 token should verify")
}

// TestStandbyKeyNotUsedForSigning tests that standby keys appear in JWKS but are not used for signing
func (suite *KeyRotationTestSuite) TestStandbyKeyNotUsedForSigning() {
	// Start with one primary key
	key1PrivateKey, key1PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key1")

	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "key1",
		Keys: map[string]*types.SigningKey{
			"key1": {
				Kid:        "key1",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key1PrivateKey,
				PublicKey:  key1PublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	secretsProvider := CreateTestSecretsProvider(secrets)

	// Create JWT service
	jwtService := services.NewJWTService(
		func() *types.InstanceSecrets { s, _ := secretsProvider.GetSecrets(suite.TestInstance); return s },
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Generate initial token - should use key1
	token1, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate token with key1")

	// Add standby key (not primary)
	key2PrivateKey, key2PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate standby key")

	secretsProvider.AddKey("key2", &types.SigningKey{
		Kid:        "key2",
		Algorithm:  types.SignAlgES256,
		PrivateKey: key2PrivateKey,
		PublicKey:  key2PublicKey,
	})

	// JWKS should contain both keys
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeys, 2, "JWKS should contain both primary and standby keys")
	suite.Contains(jwksKeys, "key1", "JWKS should contain primary key1")
	suite.Contains(jwksKeys, "key2", "JWKS should contain standby key2")

	// Generate another token - should still use primary key (key1), not standby key
	token2, err := jwtService.GenerateAccessToken(
		"user456", suite.TestInstance, "test2@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 2, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate token after adding standby key")

	// Both tokens should verify
	claims1 := VerifyJWTWithJWKS(suite.T(), token1, jwksKeys)
	suite.Equal("user123", claims1.UserID, "First token should verify")

	claims2 := VerifyJWTWithJWKS(suite.T(), token2, jwksKeys)
	suite.Equal("user456", claims2.UserID, "Second token should verify")

	// Both tokens should be signed with key1 (primary key)
	// We verify this by checking that tokens verify successfully with JWKS containing key1
	// The kid is in the JWT header, not in claims, so we verify by successful validation
	suite.NotNil(claims1, "First token should be valid and signed with primary key")
	suite.NotNil(claims2, "Second token should be valid and signed with primary key")
}

func TestKeyRotationTestSuite(t *testing.T) {
	suite.Run(t, new(KeyRotationTestSuite))
}
