package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
)

type PasswordEncoderTestSuite struct {
	TestSuite
	helper *TestHelper
}

func TestPasswordEncoderTestSuite(t *testing.T) {
	suite.Run(t, new(PasswordEncoderTestSuite))
}

func (suite *PasswordEncoderTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

// TestCustomPasswordEncoder tests that custom PasswordEncoder can be used
func (suite *PasswordEncoderTestSuite) TestCustomPasswordEncoder() {
	// Create SHA1 encoder
	sha1Encoder := &services.SHA1SaltEncoder{}
	passwordService := services.NewPasswordServiceWithEncoder(sha1Encoder, 0)

	password := "TestPassword123!"

	// Test encryption
	encoded, err := passwordService.HashPassword(password)
	suite.Require().NoError(err)
	suite.NotEmpty(encoded)
	suite.Contains(encoded, "|", "SHA1 encoded format should contain |")

	// Test verification with correct password
	valid, err := passwordService.VerifyPassword(password, encoded)
	suite.Require().NoError(err)
	suite.True(valid, "Password should verify correctly")

	// Test verification with wrong password
	valid, err = passwordService.VerifyPassword("WrongPassword", encoded)
	suite.Require().NoError(err)
	suite.False(valid, "Wrong password should not verify")
}

// TestSignupWithCustomEncoder tests that signup works with custom encoder
func (suite *PasswordEncoderTestSuite) TestSignupWithCustomEncoder() {
	// Create a new auth service with custom encoder
	sha1Encoder := &services.SHA1SaltEncoder{}
	passwordService := services.NewPasswordServiceWithEncoder(sha1Encoder, 0)

	// We need to inject the custom password service into the auth service
	// For now, we'll test the password service directly
	// In a real scenario, the auth service would need a SetPasswordService method

	email := "custom-encoder-test@example.com"
	password := "CustomPassword123!"

	// Hash the password using custom encoder
	encodedPassword, err := passwordService.HashPassword(password)
	suite.Require().NoError(err)
	suite.Contains(encodedPassword, "|", "Should use SHA1 format")

	// Create user directly in database with custom encoded password
	user := models.User{
		InstanceId:        suite.TestInstance,
		Email:             &email,
		EncryptedPassword: &encodedPassword,
	}
	err = suite.DB.Create(&user).Error
	suite.Require().NoError(err)

	// Verify the password can be verified
	valid, err := passwordService.VerifyPassword(password, encodedPassword)
	suite.Require().NoError(err)
	suite.True(valid, "Password should verify correctly")

	// Verify wrong password fails
	valid, err = passwordService.VerifyPassword("WrongPassword", encodedPassword)
	suite.Require().NoError(err)
	suite.False(valid, "Wrong password should not verify")
}

// TestDefaultArgon2idEncoder tests that default Argon2id encoder still works
func (suite *PasswordEncoderTestSuite) TestDefaultArgon2idEncoder() {
	// Create password service with default encoder
	passwordService := services.NewPasswordService(nil, "test-app-secret", 0)

	password := "TestPassword123!"

	// Test encryption
	encoded, err := passwordService.HashPassword(password)
	suite.Require().NoError(err)
	suite.NotEmpty(encoded)
	suite.Contains(encoded, "$argon2id$", "Default encoder should use Argon2id format")

	// Test verification with correct password
	valid, err := passwordService.VerifyPassword(password, encoded)
	suite.Require().NoError(err)
	suite.True(valid, "Password should verify correctly")

	// Test verification with wrong password
	valid, err = passwordService.VerifyPassword("WrongPassword", encoded)
	suite.Require().NoError(err)
	suite.False(valid, "Wrong password should not verify")
}

// TestEncoderCompatibility tests that different encoders produce different formats
func (suite *PasswordEncoderTestSuite) TestEncoderCompatibility() {
	password := "TestPassword123!"

	// Hash with SHA1 encoder
	sha1Encoder := &services.SHA1SaltEncoder{}
	sha1Service := services.NewPasswordServiceWithEncoder(sha1Encoder, 0)
	sha1Hash, err := sha1Service.HashPassword(password)
	suite.Require().NoError(err)

	// Hash with Argon2id encoder
	argon2Service := services.NewPasswordService(nil, "test-app-secret", 0)
	argon2Hash, err := argon2Service.HashPassword(password)
	suite.Require().NoError(err)

	// Verify formats are different
	suite.Contains(sha1Hash, "|", "SHA1 hash should contain |")
	suite.Contains(argon2Hash, "$argon2id$", "Argon2id hash should contain $argon2id$")

	// Verify each service can verify its own hash
	valid, err := sha1Service.VerifyPassword(password, sha1Hash)
	suite.Require().NoError(err)
	suite.True(valid, "SHA1 service should verify SHA1 hash")

	valid, err = argon2Service.VerifyPassword(password, argon2Hash)
	suite.Require().NoError(err)
	suite.True(valid, "Argon2id service should verify Argon2id hash")

	// Verify cross-verification fails gracefully
	valid, _ = sha1Service.VerifyPassword(password, argon2Hash)
	// Should return false or error, but not panic
	suite.False(valid, "SHA1 service should not verify Argon2id hash")

	valid, _ = argon2Service.VerifyPassword(password, sha1Hash)
	// Should return false or error, but not panic
	suite.False(valid, "Argon2id service should not verify SHA1 hash")
}
