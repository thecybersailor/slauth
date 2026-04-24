package services

import (
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/types"
)

func TestNormalizeAuthServiceConfig_PreservesNestedDefaults(t *testing.T) {
	cfg := config.AuthServiceConfig{
		SecurityConfig: &config.SecurityConfig{
			PasswordUpdateConfig: config.PasswordUpdateConfig{
				UpdateRequiredAAL:   types.AALLevel1,
				RevokeOtherSessions: false,
			},
		},
	}

	normalized := NormalizeAuthServiceConfig(&cfg)
	if normalized.SecurityConfig == nil {
		t.Fatalf("expected normalized security config")
	}
	if normalized.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL != types.AALLevel1 {
		t.Fatalf("expected update_required_aal %q, got %q", types.AALLevel1, normalized.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL)
	}
	if normalized.SecurityConfig.PasswordUpdateConfig.RevokeOtherSessions {
		t.Fatalf("expected revoke_other_sessions to remain false")
	}
	if normalized.SecurityConfig.PasswordUpdateConfig.RateLimit.MaxRequests != 5 {
		t.Fatalf("expected rate limit max_requests 5, got %d", normalized.SecurityConfig.PasswordUpdateConfig.RateLimit.MaxRequests)
	}
	if normalized.SecurityConfig.PasswordUpdateConfig.RateLimit.WindowDuration != time.Hour {
		t.Fatalf("expected rate limit window 1h, got %s", normalized.SecurityConfig.PasswordUpdateConfig.RateLimit.WindowDuration)
	}
	if normalized.SecurityConfig.PasswordUpdateConfig.RateLimit.Description != "Password update rate limit per user" {
		t.Fatalf("expected rate limit description to be preserved, got %q", normalized.SecurityConfig.PasswordUpdateConfig.RateLimit.Description)
	}
}

func TestApplyAuthServiceConfigPatch_DoesNotResetSiblingFields(t *testing.T) {
	current := config.NewDefaultAuthServiceConfig()
	accessTokenTTL := int64(1800)
	patch := config.AuthServiceConfigPatch{
		SessionConfig: &config.SessionConfigPatch{
			AccessTokenTTL: &accessTokenTTL,
		},
	}

	next := ApplyAuthServiceConfigPatch(current, &patch)
	if next.SessionConfig == nil {
		t.Fatalf("expected session config")
	}
	if next.SessionConfig.AccessTokenTTL != accessTokenTTL {
		t.Fatalf("expected access_token_ttl %d, got %d", accessTokenTTL, next.SessionConfig.AccessTokenTTL)
	}
	if !next.SessionConfig.RevokeCompromisedRefreshTokens {
		t.Fatalf("expected revoke_compromised_refresh_tokens to remain true")
	}
	if next.SessionConfig.EnforceSingleSessionPerUser {
		t.Fatalf("expected enforce_single_session_per_user to remain false")
	}
	if next.SessionConfig.RefreshTokenReuseInterval != 10 {
		t.Fatalf("expected refresh_token_reuse_interval 10, got %d", next.SessionConfig.RefreshTokenReuseInterval)
	}
	if next.SessionConfig.RefreshTokenTTL != 7*24*3600 {
		t.Fatalf("expected refresh_token_ttl 604800, got %d", next.SessionConfig.RefreshTokenTTL)
	}
}

func TestApplyAuthServiceConfigPatch_PreservesTopLevelBoolPointers(t *testing.T) {
	current := config.NewDefaultAuthServiceConfig()
	confirmEmail := false
	updateRequiredAAL := types.AALLevel1
	revokeOtherSessions := false
	patch := config.AuthServiceConfigPatch{
		ConfirmEmail: &confirmEmail,
		SecurityConfig: &config.SecurityConfigPatch{
			PasswordUpdateConfig: &config.PasswordUpdateConfigPatch{
				UpdateRequiredAAL:   &updateRequiredAAL,
				RevokeOtherSessions: &revokeOtherSessions,
			},
		},
	}

	next := ApplyAuthServiceConfigPatch(current, &patch)
	if next.AllowNewUsers == nil || !*next.AllowNewUsers {
		t.Fatalf("expected allow_new_users to remain true")
	}
	if next.ConfirmEmail == nil || *next.ConfirmEmail {
		t.Fatalf("expected confirm_email to be updated to false")
	}
}

func TestNormalizeAuthServiceConfigFromRaw_DoesNotAliasDefaultBoolPointers(t *testing.T) {
	raw := []byte(`{"allow_new_users":true,"confirm_email":false}`)

	loaded := NormalizeAuthServiceConfigFromRaw(raw)
	if loaded.AllowNewUsers == nil || !*loaded.AllowNewUsers {
		t.Fatalf("expected allow_new_users to remain true after raw normalization")
	}
	if loaded.ConfirmEmail == nil || *loaded.ConfirmEmail {
		t.Fatalf("expected confirm_email to be false after raw normalization")
	}
}
