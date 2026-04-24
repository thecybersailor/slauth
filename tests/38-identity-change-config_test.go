package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/types"
)

type IdentityChangeConfigTestSuite struct {
	TestSuite
}

func (suite *IdentityChangeConfigTestSuite) TestIdentityChangeConfigDefaults() {
	cfg := suite.AuthService.GetConfig()
	suite.Require().NotNil(cfg)
	suite.Require().NotNil(cfg.SecurityConfig)

	suite.Equal(types.AALLevel2, cfg.SecurityConfig.EmailChangeConfig.RequiredAAL)
	suite.False(cfg.SecurityConfig.EmailChangeConfig.RequireCurrentValueConfirmation)
	suite.Equal(5, cfg.SecurityConfig.EmailChangeConfig.RateLimit.MaxRequests)
	suite.Equal(time.Hour, cfg.SecurityConfig.EmailChangeConfig.RateLimit.WindowDuration)

	suite.Equal(types.AALLevel2, cfg.SecurityConfig.PhoneChangeConfig.RequiredAAL)
	suite.False(cfg.SecurityConfig.PhoneChangeConfig.RequireCurrentValueConfirmation)
	suite.Equal(5, cfg.SecurityConfig.PhoneChangeConfig.RateLimit.MaxRequests)
	suite.Equal(time.Hour, cfg.SecurityConfig.PhoneChangeConfig.RateLimit.WindowDuration)
}

func (suite *IdentityChangeConfigTestSuite) TestIdentityChangeConfigPersistenceAndMerge() {
	current := suite.AuthService.GetConfig()
	suite.Require().NotNil(current)
	suite.Require().NotNil(current.SecurityConfig)

	update := config.NewDefaultAuthServiceConfig()
	update.SecurityConfig = &config.SecurityConfig{
		EmailChangeConfig: config.IdentityChangeConfig{
			RequiredAAL:                     types.AALLevel1,
			RequireCurrentValueConfirmation: true,
			RateLimit: config.RateLimit{
				MaxRequests:    2,
				WindowDuration: 2 * time.Hour,
				Description:    "Email change rate limit",
			},
		},
		PhoneChangeConfig: config.IdentityChangeConfig{
			RequiredAAL:                     types.AALLevel2,
			RequireCurrentValueConfirmation: true,
			RateLimit: config.RateLimit{
				MaxRequests:    3,
				WindowDuration: 3 * time.Hour,
				Description:    "Phone change rate limit",
			},
		},
	}

	suite.Require().NoError(suite.AuthService.SaveConfig(update))

	reloaded := suite.AuthService.GetConfig()
	suite.Require().NotNil(reloaded)
	suite.Require().NotNil(reloaded.SecurityConfig)

	suite.Equal(types.AALLevel1, reloaded.SecurityConfig.EmailChangeConfig.RequiredAAL)
	suite.True(reloaded.SecurityConfig.EmailChangeConfig.RequireCurrentValueConfirmation)
	suite.Equal(2, reloaded.SecurityConfig.EmailChangeConfig.RateLimit.MaxRequests)
	suite.Equal(2*time.Hour, reloaded.SecurityConfig.EmailChangeConfig.RateLimit.WindowDuration)

	suite.Equal(types.AALLevel2, reloaded.SecurityConfig.PhoneChangeConfig.RequiredAAL)
	suite.True(reloaded.SecurityConfig.PhoneChangeConfig.RequireCurrentValueConfirmation)
	suite.Equal(3, reloaded.SecurityConfig.PhoneChangeConfig.RateLimit.MaxRequests)
	suite.Equal(3*time.Hour, reloaded.SecurityConfig.PhoneChangeConfig.RateLimit.WindowDuration)

	suite.Equal(current.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL, reloaded.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL)
	suite.Equal(current.SecurityConfig.PasswordUpdateConfig.RevokeOtherSessions, reloaded.SecurityConfig.PasswordUpdateConfig.RevokeOtherSessions)
	suite.Equal(current.SecurityConfig.PasswordStrengthConfig.MinScore, reloaded.SecurityConfig.PasswordStrengthConfig.MinScore)
}

func TestIdentityChangeConfigTestSuite(t *testing.T) {
	suite.Run(t, new(IdentityChangeConfigTestSuite))
}
