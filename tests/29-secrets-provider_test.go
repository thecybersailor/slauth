package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type SecretsProviderTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SecretsProviderTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// Test case for StaticSecretsProvider
// Tests that the provider correctly returns configured secrets
func (suite *SecretsProviderTestSuite) TestStaticSecretsProvider() {
	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "test-primary",
		Keys: map[string]*types.SigningKey{
			"test-primary": {
				Kid:        "test-primary",
				Algorithm:  types.SignAlgES256,
				PrivateKey: "test-private-key",
				PublicKey:  "test-public-key",
			},
			"test-secondary": {
				Kid:        "test-secondary",
				Algorithm:  types.SignAlgRS256,
				PrivateKey: "test-rsa-private",
				PublicKey:  "test-rsa-public",
			},
		},
		AppSecret: "test-app-secret",
	}

	provider := services.NewStaticSecretsProvider(secrets)

	// Test GetSecrets
	result, err := provider.GetSecrets(suite.TestInstance)
	suite.NoError(err, "GetSecrets should not fail")
	suite.NotNil(result, "GetSecrets should return non-nil result")

	suite.Equal("test-primary", result.PrimaryKeyId, "Primary key ID should match")
	suite.Equal("test-app-secret", result.AppSecret, "App secret should match")
	suite.Equal(2, len(result.Keys), "Should have 2 keys")

	// Check primary key
	primaryKey, exists := result.Keys["test-primary"]
	suite.True(exists, "Primary key should exist")
	suite.Equal(types.SignAlgES256, primaryKey.Algorithm, "Primary key algorithm should be ES256")
	suite.Equal("test-private-key", primaryKey.PrivateKey, "Private key should match")
	suite.Equal("test-public-key", primaryKey.PublicKey, "Public key should match")

	// Check secondary key
	secondaryKey, exists := result.Keys["test-secondary"]
	suite.True(exists, "Secondary key should exist")
	suite.Equal(types.SignAlgRS256, secondaryKey.Algorithm, "Secondary key algorithm should be RS256")
}

// Test case for StaticSecretsProvider with empty secrets
func (suite *SecretsProviderTestSuite) TestStaticSecretsProviderEmpty() {
	secrets := &types.InstanceSecrets{
		Keys: make(map[string]*types.SigningKey),
	}

	provider := services.NewStaticSecretsProvider(secrets)

	result, err := provider.GetSecrets(suite.TestInstance)
	suite.NoError(err, "GetSecrets should not fail even with empty secrets")
	suite.NotNil(result, "GetSecrets should return non-nil result")
	suite.Equal(0, len(result.Keys), "Should have 0 keys")
}

// Test case for StaticSecretsProvider consistency
// Verifies that provider always returns the same secrets regardless of instance ID
func (suite *SecretsProviderTestSuite) TestStaticSecretsProviderConsistency() {
	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "test-key",
		Keys: map[string]*types.SigningKey{
			"test-key": {
				Kid:        "test-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: "test-private",
				PublicKey:  "test-public",
			},
		},
		AppSecret: "test-app",
	}

	provider := services.NewStaticSecretsProvider(secrets)

	// Call multiple times with different instance IDs
	result1, _ := provider.GetSecrets("instance1")
	result2, _ := provider.GetSecrets("instance2")

	// Should return the same secrets regardless of instance ID
	suite.Equal(result1.PrimaryKeyId, result2.PrimaryKeyId, "Provider should return same primary key ID")
	suite.Equal(result1.AppSecret, result2.AppSecret, "Provider should return same app secret")
}

func TestSecretsProviderTestSuite(t *testing.T) {
	suite.Run(t, new(SecretsProviderTestSuite))
}
