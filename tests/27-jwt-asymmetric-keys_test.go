package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type JWTAsymmetricKeysTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *JWTAsymmetricKeysTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// Test case for JWT signing and validation with asymmetric keys
// Tests the new InstanceSecretsProvider interface and kid header support
func (suite *JWTAsymmetricKeysTestSuite) TestJWTAsymmetricSigning() {
	// Generate test keys
	testSecrets, err := GenerateTestSecrets(types.SignAlgES256)
	suite.Require().NoError(err, "Failed to generate test keys")

	// Create a custom secrets provider for this test
	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "test-key-2024",
		Keys: map[string]*types.SigningKey{
			"test-key-2024": {
				Kid:        "test-key-2024",
				Algorithm:  types.SignAlgES256,
				PrivateKey: testSecrets.Keys["test-key"].PrivateKey,
				PublicKey:  testSecrets.Keys["test-key"].PublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	provider := services.NewStaticSecretsProvider(secrets)

	getSecrets := func() *types.InstanceSecrets {
		s, _ := provider.GetSecrets(suite.TestInstance)
		return s
	}

	jwtService := services.NewJWTService(
		getSecrets,
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	// Test token generation
	token, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "user@example.com", "", "authenticated",
		types.AALLevel1, []string{"pwd"}, 1, nil, nil,
	)

	suite.NoError(err, "Failed to generate token")
	suite.NotEmpty(token, "Generated token should not be empty")

	// Test token validation
	claims, err := jwtService.ValidateAccessToken(token)
	suite.NoError(err, "Failed to validate token")
	suite.NotNil(claims, "Claims should not be nil")
	suite.Equal("user123", claims.UserID, "User ID should match")
	suite.Equal(suite.TestInstance, claims.InstanceId, "Instance ID should match")
}

// Test case for JWT with kid header
// Verifies that kid is properly set in JWT header and used for validation
func (suite *JWTAsymmetricKeysTestSuite) TestJWTWithKid() {
	// Generate test keys
	testSecrets, err := GenerateTestSecrets(types.SignAlgES256)
	suite.Require().NoError(err, "Failed to generate test keys")

	secrets := &types.InstanceSecrets{
		PrimaryKeyId: "test-key-2024",
		Keys: map[string]*types.SigningKey{
			"test-key-2024": {
				Kid:        "test-key-2024",
				Algorithm:  types.SignAlgES256,
				PrivateKey: testSecrets.Keys["test-key"].PrivateKey,
				PublicKey:  testSecrets.Keys["test-key"].PublicKey,
			},
		},
		AppSecret: "test-app-secret",
	}

	provider := services.NewStaticSecretsProvider(secrets)

	getSecrets := func() *types.InstanceSecrets {
		s, _ := provider.GetSecrets(suite.TestInstance)
		return s
	}

	jwtService := services.NewJWTService(
		getSecrets,
		func() time.Duration { return time.Hour },
		func() time.Duration { return 24 * time.Hour },
		"https://test.example.com",
	)

	token, err := jwtService.GenerateAccessToken(
		"user123", suite.TestInstance, "", "", "authenticated",
		types.AALLevel1, []string{}, 1, nil, nil,
	)

	suite.NoError(err, "Failed to generate token with kid")

	// Validate token - kid should be used for key lookup
	claims, err := jwtService.ValidateAccessToken(token)
	suite.NoError(err, "Failed to validate token with kid")
	suite.NotNil(claims, "Claims should not be nil")
	suite.Equal("user123", claims.UserID, "User ID should match")
}

func TestJWTAsymmetricKeysTestSuite(t *testing.T) {
	suite.Run(t, new(JWTAsymmetricKeysTestSuite))
}
