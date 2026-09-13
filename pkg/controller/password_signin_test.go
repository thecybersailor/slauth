package controller

import (
	"context"
	"net/http"
	"strings"
	"testing"

	authconfig "github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/services"
)

func TestPasswordSigninLimitReturnsBeforeAuthentication(t *testing.T) {
	router, _, authService := newPhoneOTPTestRouter(t)
	authService.SetEmailAuthLimiter(services.NewEmailAuthLimiter(&denyPasswordSigninRateLimiter{}))

	response := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{
		"email":    "missing@example.com",
		"password": "wrong password",
	})
	if !strings.Contains(response.Body.String(), "auth.over_request_rate_limit") {
		t.Fatalf("password signin body = %s, want rate limit error", response.Body.String())
	}
}

type denyPasswordSigninRateLimiter struct{}

func (d *denyPasswordSigninRateLimiter) CheckAndRecordRequest(_ context.Context, _ any, _ string, _ string, _ authconfig.RateLimit, _ *authconfig.AuthServiceConfig) (bool, error) {
	return false, nil
}
