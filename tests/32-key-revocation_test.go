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

type KeyRevocationTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *KeyRevocationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestKeyRevocationImmediate tests that key revocation takes effect immediately
func (suite *KeyRevocationTestSuite) TestKeyRevocationImmediate() {
	// Generate test keys
	key1PrivateKey, key1PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key1")

	key2PrivateKey, key2PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key2")

	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "key1",
		Keys: map[string]*types.SigningKey{
			"key1": {
				Kid:        "key1",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key1PrivateKey,
				PublicKey:  key1PublicKey,
			},
			"key2": {
				Kid:        "key2",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key2PrivateKey,
				PublicKey:  key2PublicKey,
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

	// Generate token with key1
	token, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate token with key1")

	// Create JWKS endpoint
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Before revocation: token should verify
	jwksKeysBefore := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeysBefore, 2, "JWKS should contain both keys before revocation")
	suite.Contains(jwksKeysBefore, "key1", "JWKS should contain key1")
	suite.Contains(jwksKeysBefore, "key2", "JWKS should contain key2")

	claimsBefore := VerifyJWTWithJWKS(suite.T(), token, jwksKeysBefore)
	suite.Equal("user123", claimsBefore.UserID, "Token should verify before revocation")

	// Revoke key1
	secretsProvider.RemoveKey("key1")

	// After revocation: token should fail verification immediately
	jwksKeysAfter := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeysAfter, 1, "JWKS should contain only key2 after key1 revocation")
	suite.Contains(jwksKeysAfter, "key2", "JWKS should contain key2")
	suite.NotContains(jwksKeysAfter, "key1", "JWKS should not contain revoked key1")

	// Token signed with revoked key1 should fail
	_, err = jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		suite.True(ok, "Token should have kid header")
		suite.Equal("key1", kid, "Token should be signed with key1")

		_, exists := jwksKeysAfter[kid]
		suite.False(exists, "Revoked key1 should not exist in JWKS")
		return nil, fmt.Errorf("kid %s not found in JWKS (key revoked)", kid)
	})
	suite.Error(err, "Token signed with revoked key should fail verification immediately")
}

// TestRevokedKeyNotInJWKS tests that revoked keys are excluded from JWKS response
func (suite *KeyRevocationTestSuite) TestRevokedKeyNotInJWKS() {
	// Generate test keys
	key1PrivateKey, key1PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key1")

	key2PrivateKey, key2PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key2")

	key3PrivateKey, key3PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key3")

	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "key1",
		Keys: map[string]*types.SigningKey{
			"key1": {
				Kid:        "key1",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key1PrivateKey,
				PublicKey:  key1PublicKey,
			},
			"key2": {
				Kid:        "key2",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key2PrivateKey,
				PublicKey:  key2PublicKey,
			},
			"key3": {
				Kid:        "key3",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key3PrivateKey,
				PublicKey:  key3PublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	secretsProvider := CreateTestSecretsProvider(secrets)

	// Create JWKS endpoint
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)

	// Initially all keys should be in JWKS
	jwksKeysInitial := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeysInitial, 3, "JWKS should contain all three keys initially")
	suite.Contains(jwksKeysInitial, "key1", "JWKS should contain key1")
	suite.Contains(jwksKeysInitial, "key2", "JWKS should contain key2")
	suite.Contains(jwksKeysInitial, "key3", "JWKS should contain key3")

	// Revoke key2
	secretsProvider.RemoveKey("key2")

	// JWKS should exclude revoked key2 but include active keys
	jwksKeysAfterRevoke := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeysAfterRevoke, 2, "JWKS should contain only active keys after revocation")
	suite.Contains(jwksKeysAfterRevoke, "key1", "JWKS should contain active key1")
	suite.Contains(jwksKeysAfterRevoke, "key3", "JWKS should contain active key3")
	suite.NotContains(jwksKeysAfterRevoke, "key2", "JWKS should not contain revoked key2")

	// Revoke key1
	secretsProvider.RemoveKey("key1")

	// JWKS should now only contain key3
	jwksKeysAfterSecondRevoke := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")
	suite.Len(jwksKeysAfterSecondRevoke, 1, "JWKS should contain only key3 after second revocation")
	suite.Contains(jwksKeysAfterSecondRevoke, "key3", "JWKS should contain active key3")
	suite.NotContains(jwksKeysAfterSecondRevoke, "key1", "JWKS should not contain revoked key1")
	suite.NotContains(jwksKeysAfterSecondRevoke, "key2", "JWKS should not contain revoked key2")
}

// TestCannotSignWithRevokedKey tests that revoked primary key cannot be used for signing
func (suite *KeyRevocationTestSuite) TestCannotSignWithRevokedKey() {
	// Generate test keys
	key1PrivateKey, key1PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key1")

	key2PrivateKey, key2PublicKey, err := GenerateES256KeyPair()
	suite.Require().NoError(err, "Failed to generate key2")

	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "key1",
		Keys: map[string]*types.SigningKey{
			"key1": {
				Kid:        "key1",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key1PrivateKey,
				PublicKey:  key1PublicKey,
			},
			"key2": {
				Kid:        "key2",
				Algorithm:  types.SignAlgES256,
				PrivateKey: key2PrivateKey,
				PublicKey:  key2PublicKey,
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

	// Generate token with key1 (primary)
	token1, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "test@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)
	suite.Require().NoError(err, "Failed to generate token with key1")

	// Revoke primary key1
	secretsProvider.RemoveKey("key1")

	// Attempting to generate new token should fail because primary key is revoked
	_, err = jwtService.GenerateAccessToken(
		"user456", suite.TestInstance, "test2@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 2, nil, nil,
	)
	suite.Error(err, "Should fail to generate token when primary key is revoked")

	// Set key2 as primary
	secretsProvider.SetPrimaryKey("key2")

	// Now should be able to generate tokens with key2
	token2, err := jwtService.GenerateAccessToken(
		"user456", suite.TestInstance, "test2@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 2, nil, nil,
	)
	suite.Require().NoError(err, "Should be able to generate token with new primary key2")

	// Verify token2 works
	gin.SetMode(gin.TestMode)
	jwksRouter := gin.New()
	jwksRouter.GET("/.well-known/jwks.json", controller.HandleJWKS(secretsProvider, suite.TestInstance))

	jwksHelper := NewTestHelper(suite.DB, jwksRouter, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
	jwksKeys := jwksHelper.FetchJWKSKeys(suite.T(), "/.well-known/jwks.json")

	claims2 := VerifyJWTWithJWKS(suite.T(), token2, jwksKeys)
	suite.Equal("user456", claims2.UserID, "Token signed with new primary key should verify")

	// Token1 (signed with revoked key1) should fail
	_, err = jwt.ParseWithClaims(token1, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		suite.True(ok, "Token should have kid header")
		suite.Equal("key1", kid, "Token should be signed with revoked key1")

		_, exists := jwksKeys[kid]
		suite.False(exists, "Revoked key1 should not exist in JWKS")
		return nil, fmt.Errorf("kid %s not found in JWKS (key revoked)", kid)
	})
	suite.Error(err, "Token signed with revoked key should fail verification")
}

func TestKeyRevocationTestSuite(t *testing.T) {
	suite.Run(t, new(KeyRevocationTestSuite))
}
