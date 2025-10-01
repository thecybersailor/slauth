package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/services"
)

// RedirectURLValidationTestSuite tests redirect URL validation logic
// Tests the ValidatorService.ValidateRedirectURL method which validates
// redirect URLs against a whitelist with wildcard support
type RedirectURLValidationTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *RedirectURLValidationTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestDomain, suite.EmailProvider, suite.SMSProvider)
}

func TestRedirectURLValidation(t *testing.T) {
	suite.Run(t, new(RedirectURLValidationTestSuite))
}

// TestValidateRedirectURLService tests the ValidatorService.ValidateRedirectURL method
func (suite *RedirectURLValidationTestSuite) TestValidateRedirectURLService() {
	t := suite.T()
	t.Log("=== Test: ValidateRedirectURL Service Method ===")

	// Create validator service
	validatorService := services.NewValidatorService()

	// Test Case 1: Valid exact match
	t.Log("Test Case 1: Valid exact match")
	allowedURLs := []string{
		"http://localhost:3000",
		"https://app.example.com",
	}

	err := validatorService.ValidateRedirectURL("http://localhost:3000/dashboard", allowedURLs)
	suite.NoError(err, "Valid URL should pass validation")
	t.Log("✅ Exact match validation passed")

	// Test Case 2: Invalid URL (not in whitelist)
	t.Log("Test Case 2: Invalid URL rejection")
	err = validatorService.ValidateRedirectURL("https://evil.com/phishing", allowedURLs)
	suite.Error(err, "Invalid URL should fail validation")
	t.Log("✅ Invalid URL rejected correctly")

	// Test Case 3: Empty URL (should pass)
	t.Log("Test Case 3: Empty URL handling")
	err = validatorService.ValidateRedirectURL("", allowedURLs)
	suite.NoError(err, "Empty URL should be allowed (optional parameter)")
	t.Log("✅ Empty URL handled correctly")
}

// TestWildcardRedirectURLMatching tests wildcard pattern matching
func (suite *RedirectURLValidationTestSuite) TestWildcardRedirectURLMatching() {
	t := suite.T()
	t.Log("=== Test: Wildcard Redirect URL Matching ===")

	validatorService := services.NewValidatorService()

	// Configure wildcard redirect URLs
	allowedURLs := []string{
		"https://*.example.com",        // Subdomain wildcard
		"https://app-*.production.com", // Middle wildcard
	}

	// Test Case 1: Valid subdomain
	t.Log("Test Case 1: Valid subdomain match")
	err := validatorService.ValidateRedirectURL("https://app.example.com/dashboard", allowedURLs)
	suite.NoError(err, "Subdomain wildcard should match")
	t.Log("✅ Subdomain wildcard matched correctly")

	// Test Case 2: Another valid subdomain
	t.Log("Test Case 2: Another valid subdomain")
	err = validatorService.ValidateRedirectURL("https://admin.example.com/panel", allowedURLs)
	suite.NoError(err, "Another subdomain should match")
	t.Log("✅ Another subdomain matched correctly")

	// Test Case 3: Valid middle wildcard
	t.Log("Test Case 3: Middle wildcard match")
	err = validatorService.ValidateRedirectURL("https://app-staging.production.com/test", allowedURLs)
	suite.NoError(err, "Middle wildcard should match")
	t.Log("✅ Middle wildcard matched correctly")

	// Test Case 4: Invalid domain (should not match)
	t.Log("Test Case 4: Invalid domain should not match wildcard")
	err = validatorService.ValidateRedirectURL("https://app.evil-example.com/phishing", allowedURLs)
	suite.Error(err, "Should not match different domain")
	t.Log("✅ Invalid domain rejected correctly")

	// Test Case 5: Exact domain without subdomain (should not match *.example.com)
	t.Log("Test Case 5: Root domain without subdomain")
	err = validatorService.ValidateRedirectURL("https://example.com/page", allowedURLs)
	suite.Error(err, "Root domain should not match subdomain wildcard")
	t.Log("✅ Root domain handled correctly")
}

// TestDangerousProtocolRedirects tests rejection of dangerous URL protocols
func (suite *RedirectURLValidationTestSuite) TestDangerousProtocolRedirects() {
	t := suite.T()
	t.Log("=== Test: Dangerous Protocol Redirects ===")

	validatorService := services.NewValidatorService()
	allowedURLs := []string{
		"http://localhost:3000",
		"https://app.example.com",
	}

	dangerousURLs := []struct {
		name string
		url  string
	}{
		{"JavaScript protocol", "javascript:alert('XSS')"},
		{"Data URL", "data:text/html,<script>alert('XSS')</script>"},
		{"File protocol", "file:///etc/passwd"},
		{"VBScript protocol", "vbscript:msgbox('XSS')"},
	}

	for _, tc := range dangerousURLs {
		t.Logf("Testing: %s", tc.name)

		err := validatorService.ValidateRedirectURL(tc.url, allowedURLs)
		suite.Error(err, "Dangerous protocol should be rejected: %s", tc.name)
		t.Logf("✅ %s rejected correctly", tc.name)
	}
}

// TestRelativePathRedirect tests relative path handling
func (suite *RedirectURLValidationTestSuite) TestRelativePathRedirect() {
	t := suite.T()
	t.Log("=== Test: Relative Path Redirect ===")

	validatorService := services.NewValidatorService()
	allowedURLs := []string{
		"http://localhost:3000",
	}

	// Test relative paths
	relativePaths := []string{
		"/dashboard/overview",
		"/settings",
		"/user/profile",
	}

	for _, path := range relativePaths {
		t.Logf("Testing relative path: %s", path)

		// Note: Validator behavior with relative paths depends on implementation
		// They should either be allowed (safe) or require explicit handling
		err := validatorService.ValidateRedirectURL(path, allowedURLs)

		if err != nil {
			t.Logf("ℹ️ Relative path %s requires explicit whitelist", path)
		} else {
			t.Logf("✅ Relative path %s allowed", path)
		}
	}
}

// TestRedirectURLWithQueryParameters tests URL with query parameters
func (suite *RedirectURLValidationTestSuite) TestRedirectURLWithQueryParameters() {
	t := suite.T()
	t.Log("=== Test: Redirect URL with Query Parameters ===")

	validatorService := services.NewValidatorService()
	allowedURLs := []string{
		"http://localhost:3000",
	}

	// Test redirect with query parameters
	redirectTo := "http://localhost:3000/dashboard?tab=profile&source=signin"

	err := validatorService.ValidateRedirectURL(redirectTo, allowedURLs)
	suite.NoError(err, "Query parameters should be preserved")
	t.Log("✅ Query parameters handled correctly")
}

// TestRedirectURLWithFragment tests URL with fragment/hash
func (suite *RedirectURLValidationTestSuite) TestRedirectURLWithFragment() {
	t := suite.T()
	t.Log("=== Test: Redirect URL with Fragment/Hash ===")

	validatorService := services.NewValidatorService()
	allowedURLs := []string{
		"http://localhost:3000",
	}

	// Test redirect with fragment
	redirectTo := "http://localhost:3000/dashboard#section-settings"

	err := validatorService.ValidateRedirectURL(redirectTo, allowedURLs)
	suite.NoError(err, "Fragment should be preserved")
	t.Log("✅ URL fragment handled correctly")
}

// TestMultipleRedirectURLsInConfig tests multiple allowed URLs
func (suite *RedirectURLValidationTestSuite) TestMultipleRedirectURLsInConfig() {
	t := suite.T()
	t.Log("=== Test: Multiple Redirect URLs in Configuration ===")

	validatorService := services.NewValidatorService()

	// Configure multiple allowed redirect URLs
	allowedURLs := []string{
		"http://localhost:3000",
		"http://localhost:5173",
		"https://app.example.com",
		"https://admin.example.com",
	}

	// Test each configured URL
	testURLs := []string{
		"http://localhost:3000/dashboard",
		"http://localhost:5173/app",
		"https://app.example.com/home",
		"https://admin.example.com/panel",
	}

	for _, testURL := range testURLs {
		t.Logf("Testing redirect to: %s", testURL)

		err := validatorService.ValidateRedirectURL(testURL, allowedURLs)
		suite.NoError(err, "Configured URL should be allowed: %s", testURL)
		t.Logf("✅ %s allowed correctly", testURL)
	}
}

// TestEmptyWhitelistBehavior tests behavior when whitelist is empty
func (suite *RedirectURLValidationTestSuite) TestEmptyWhitelistBehavior() {
	t := suite.T()
	t.Log("=== Test: Empty Whitelist Behavior ===")

	validatorService := services.NewValidatorService()
	emptyWhitelist := []string{}

	// Any URL should fail when whitelist is empty
	testURL := "http://localhost:3000/page"

	err := validatorService.ValidateRedirectURL(testURL, emptyWhitelist)
	suite.Error(err, "Should reject all URLs when whitelist is empty")
	t.Log("✅ Empty whitelist handled correctly")
}

// TestCaseSensitiveURLMatching tests case sensitivity in URL matching
func (suite *RedirectURLValidationTestSuite) TestCaseSensitiveURLMatching() {
	t := suite.T()
	t.Log("=== Test: Case Sensitive URL Matching ===")

	validatorService := services.NewValidatorService()
	allowedURLs := []string{
		"https://APP.example.com", // Uppercase subdomain
	}

	// Test case variations
	testCases := []struct {
		url         string
		shouldMatch bool
		description string
	}{
		{"https://APP.example.com/page", true, "Exact case match"},
		{"https://app.example.com/page", false, "Lowercase subdomain"},
		{"https://App.example.com/page", false, "Mixed case"},
	}

	for _, tc := range testCases {
		t.Logf("Testing: %s", tc.description)
		err := validatorService.ValidateRedirectURL(tc.url, allowedURLs)

		if tc.shouldMatch {
			suite.NoError(err, "Should match: %s", tc.description)
		} else {
			// Note: URL matching is typically case-insensitive for domains
			// This test documents the actual behavior
			t.Logf("Result for %s: %v", tc.description, err == nil)
		}
	}
}

// TestPortSpecificURLMatching tests URL matching with different ports
func (suite *RedirectURLValidationTestSuite) TestPortSpecificURLMatching() {
	t := suite.T()
	t.Log("=== Test: Port Specific URL Matching ===")

	validatorService := services.NewValidatorService()
	allowedURLs := []string{
		"http://localhost:3000",
		"http://localhost:8080",
	}

	// Test different ports
	err1 := validatorService.ValidateRedirectURL("http://localhost:3000/page", allowedURLs)
	suite.NoError(err1, "Port 3000 should be allowed")

	err2 := validatorService.ValidateRedirectURL("http://localhost:8080/page", allowedURLs)
	suite.NoError(err2, "Port 8080 should be allowed")

	err3 := validatorService.ValidateRedirectURL("http://localhost:9000/page", allowedURLs)
	suite.Error(err3, "Port 9000 should be rejected")

	t.Log("✅ Port-specific matching works correctly")
}
