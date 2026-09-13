package controller

import (
	"net/http"
	"strings"
	"testing"

	"github.com/thecybersailor/slauth/pkg/models"
)

func TestMagicLinkLoginDisabledRejectsSendAndVerify(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	disabled := false
	cfg := authService.GetConfig()
	cfg.EnableEmailMagicLinkLogin = &disabled
	if err := authService.SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	send := doJSONRequest(t, router, http.MethodPost, "/auth/v1/otp", map[string]any{
		"email": "disabled-magic@example.com",
		"options": map[string]any{
			"emailRedirectTo":  "https://app.example.com/auth/callback",
			"shouldCreateUser": true,
		},
	})
	if !strings.Contains(send.Body.String(), "auth.otp_disabled") {
		t.Fatalf("send magic link body = %s", send.Body.String())
	}
	if emails.last != nil {
		t.Fatalf("disabled magic link sent mail: %+v", emails.last)
	}
	var users int64
	if err := db.Model(&models.User{}).Where("email = ?", "disabled-magic@example.com").Count(&users).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Fatalf("disabled magic link created %d users", users)
	}
	verify := doJSONRequest(t, router, http.MethodPost, "/auth/v1/verify", map[string]any{
		"token": "legacy-token",
		"type":  "magic_link",
	})
	if !strings.Contains(verify.Body.String(), "auth.otp_disabled") {
		t.Fatalf("verify magic link body = %s", verify.Body.String())
	}
}
