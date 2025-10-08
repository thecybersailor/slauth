package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/models"
)

type SystemSettingTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *SystemSettingTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(
		suite.DB,
		suite.Router,
		suite.TestInstance,
		suite.EmailProvider,
		suite.SMSProvider,
	)
}

func TestSystemSettingSuite(t *testing.T) {
	suite.Run(t, new(SystemSettingTestSuite))
}

func (suite *SystemSettingTestSuite) Test_01_GetInstanceConfig() {

	response := suite.helper.MakeGETRequest(suite.T(), "/admin/config")

	suite.helper.MatchObject(suite.T(), response, S{
		"instance_id": suite.TestInstance,
		"config":      S{},
	}, "Should return instance config")

	configData := response.Data.(map[string]interface{})["config"].(map[string]interface{})
	suite.NotNil(configData)

	suite.Equal(true, configData["allow_new_users"], "Default allow_new_users should be true")
	suite.Equal(false, configData["confirm_email"], "Default confirm_email should be false")
	suite.Equal(false, configData["anonymous_sign_ins"], "Default anonymous_sign_ins should be false")
	suite.Equal(10.0, configData["maximum_mfa_factors"], "Default maximum_mfa_factors should be 10")

	var instance models.AuthInstance
	err := suite.DB.Where("instance_id = ?", suite.TestInstance).First(&instance).Error
	suite.NoError(err, "Instance should be created in database")
}

func (suite *SystemSettingTestSuite) Test_02_UpdateInstanceConfig_BasicSettings() {

	getResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	currentConfig := getResponse.Data.(map[string]interface{})["config"].(map[string]interface{})

	updatedConfig := map[string]interface{}{
		"site_url":                               "http://localhost:3000",
		"auth_service_base_url":                  "http://localhost:3000/auth",
		"redirect_urls":                          []string{"http://localhost:3000", "http://localhost:5180"},
		"allow_new_users":                        false,
		"confirm_email":                          true,
		"anonymous_sign_ins":                     false,
		"enable_captcha":                         true,
		"maximum_mfa_factors":                    5,
		"maximum_mfa_factor_validation_attempts": 3,
		"max_time_allowed_for_auth_request":      10000000000,
		"session_config": map[string]interface{}{
			"access_token_ttl":  7200000000000,
			"refresh_token_ttl": 1296000000000000,
		},
		"ratelimit_config": currentConfig["ratelimit_config"],
		"security_config":  currentConfig["security_config"],
	}

	updateResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": updatedConfig,
	}, nil)

	suite.helper.MatchObject(suite.T(), updateResponse, S{
		"message": "Config updated successfully",
		"config": S{
			"allow_new_users": false,
			"confirm_email":   true,
			"enable_captcha":  true,
		},
	}, "Should update config successfully")

	var instance models.AuthInstance
	err := suite.DB.Where("instance_id = ?", suite.TestInstance).First(&instance).Error
	suite.NoError(err)

	suite.Equal(false, *instance.ConfigData.AllowNewUsers, "allow_new_users should be updated to false")
	suite.Equal(true, *instance.ConfigData.ConfirmEmail, "confirm_email should be updated to true")
	suite.Equal(true, *instance.ConfigData.EnableCaptcha, "enable_captcha should be updated to true")
	suite.Equal(5, instance.ConfigData.MaximumMfaFactors, "maximum_mfa_factors should be updated to 5")

	time.Sleep(100 * time.Millisecond)
	getAfterUpdate := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	updatedConfigData := getAfterUpdate.Data.(map[string]interface{})["config"].(map[string]interface{})

	suite.Equal(false, updatedConfigData["allow_new_users"], "Retrieved config should reflect updates")
	suite.Equal(true, updatedConfigData["confirm_email"], "Retrieved config should reflect updates")

	// Restore default config
	restoreResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": S{
			"allow_new_users": true,
			"confirm_email":   false,
		},
	}, nil)
	suite.Equal(200, restoreResponse.ResponseRecorder.Code, "Should restore default config")
}

/*
func (suite *SystemSettingTestSuite) Test_03_UpdateInstanceConfig_RegenerateSecret() {

	getResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	currentConfig := getResponse.Data.(map[string]interface{})["config"].(map[string]interface{})
	oldSecret := getResponse.Data.(map[string]interface{})["secret"].(string)


	newSecret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


	updateResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": currentConfig,
		"secret": newSecret,
	}, nil)

	suite.helper.MatchObject(suite.T(), updateResponse, S{
		"message": "Config updated successfully",
	}, "Should update secret successfully")


	var instance models.AuthInstance
	err := suite.DB.Where("instance_id = ?", suite.TestInstance).First(&instance).Error
	suite.NoError(err)
	suite.Equal(newSecret, instance.Secret, "Secret should be updated")
	suite.NotEqual(oldSecret, instance.Secret, "Secret should be different from old one")


	getAfterUpdate := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	updatedSecret := getAfterUpdate.Data.(map[string]interface{})["secret"].(string)
	suite.Equal(newSecret, updatedSecret, "Retrieved secret should be the new one")
}
*/

func (suite *SystemSettingTestSuite) Test_04_UpdateInstanceConfig_SessionSettings() {
	getResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	currentConfig := getResponse.Data.(map[string]interface{})["config"].(map[string]interface{})

	currentConfig["session_config"] = map[string]interface{}{
		"access_token_ttl":  1800,   // 30 minutes in seconds
		"refresh_token_ttl": 604800, // 7 days in seconds
	}

	updateResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": currentConfig,
	}, nil)

	suite.helper.MatchObject(suite.T(), updateResponse, S{
		"message": "Config updated successfully",
	}, "Should update secret successfully")

	var instance models.AuthInstance
	err := suite.DB.Where("instance_id = ?", suite.TestInstance).First(&instance).Error
	suite.NoError(err)

	suite.Equal(int64(1800), instance.ConfigData.SessionConfig.AccessTokenTTL)
	suite.Equal(int64(604800), instance.ConfigData.SessionConfig.RefreshTokenTTL)
}

func (suite *SystemSettingTestSuite) Test_05_UpdateInstanceConfig_URLSettings() {
	getResponse := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	currentConfig := getResponse.Data.(map[string]interface{})["config"].(map[string]interface{})

	currentConfig["site_url"] = "https://example.com"
	currentConfig["auth_service_base_url"] = "https://example.com/api/auth"
	currentConfig["redirect_urls"] = []string{
		"https://example.com",
		"https://app.example.com",
		"https://*.example.com",
	}

	updateResponse := suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": currentConfig,
	}, nil)

	suite.helper.MatchObject(suite.T(), updateResponse, S{
		"message": "Config updated successfully",
	}, "Should update secret successfully")

	var instance models.AuthInstance
	err := suite.DB.Where("instance_id = ?", suite.TestInstance).First(&instance).Error
	suite.NoError(err)

	suite.Equal("https://example.com", instance.ConfigData.SiteURL)
	suite.Equal("https://example.com/api/auth", instance.ConfigData.AuthServiceBaseUrl)

	suite.Equal(3, len(instance.ConfigData.RedirectURLs))
	suite.Equal("https://example.com", instance.ConfigData.RedirectURLs[0])
}

func (suite *SystemSettingTestSuite) Test_06_ConfigCaching() {

	getResponse1 := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	currentConfig := getResponse1.Data.(map[string]interface{})["config"].(map[string]interface{})

	currentConfig["allow_new_users"] = true
	currentConfig["confirm_email"] = false

	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": currentConfig,
	}, nil)

	getResponse2 := suite.helper.MakeGETRequest(suite.T(), "/admin/config")
	updatedConfig := getResponse2.Data.(map[string]interface{})["config"].(map[string]interface{})

	suite.Equal(true, updatedConfig["allow_new_users"], "Config should be updated immediately after save")
	suite.Equal(false, updatedConfig["confirm_email"], "Config should be updated immediately after save")
}

func (suite *SystemSettingTestSuite) Test_07_ConfigPersistence() {

	testConfig := map[string]interface{}{
		"site_url":                               "http://persistence-test.com",
		"auth_service_base_url":                  "http://persistence-test.com/auth",
		"redirect_urls":                          []string{"http://persistence-test.com"},
		"allow_new_users":                        false,
		"confirm_email":                          true,
		"anonymous_sign_ins":                     true,
		"enable_captcha":                         true,
		"maximum_mfa_factors":                    8,
		"maximum_mfa_factor_validation_attempts": 4,
		"max_time_allowed_for_auth_request":      15000000000,
		"session_config": map[string]interface{}{
			"access_token_ttl":  5400000000000,
			"refresh_token_ttl": 1814400000000000,
		},
		"ratelimit_config": map[string]interface{}{},
		"security_config":  map[string]interface{}{},
	}

	suite.helper.MakePUTRequest(suite.T(), "/admin/config", S{
		"config": testConfig,
	}, nil)

	var instance models.AuthInstance
	err := suite.DB.Where("instance_id = ?", suite.TestInstance).First(&instance).Error
	suite.NoError(err)

	suite.Equal("http://persistence-test.com", instance.ConfigData.SiteURL)
	suite.Equal(false, *instance.ConfigData.AllowNewUsers)
	suite.Equal(true, *instance.ConfigData.ConfirmEmail)
	suite.Equal(true, *instance.ConfigData.AnonymousSignIns)
	suite.Equal(true, *instance.ConfigData.EnableCaptcha)
	suite.Equal(8, instance.ConfigData.MaximumMfaFactors)
}
