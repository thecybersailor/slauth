package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
)

func TestEmailAuthLimitUsesEmailAndIPDimensions(t *testing.T) {
	checker := &recordingRateLimitChecker{allowed: []bool{true, true}}
	limiter := NewEmailAuthLimiter(checker)
	cfg := config.NewDefaultAuthServiceConfig()
	cfg.AppSecret = "limiter-secret"
	limit := config.RateLimit{MaxRequests: 5, WindowDuration: time.Minute}

	allowed, err := limiter.Check(context.Background(), EmailAuthLimitRequest{
		InstanceID: "tenant-a",
		Action:     EmailAuthActionPasswordLogin,
		Email:      " User@Example.COM ",
		IP:         "203.0.113.10",
		EmailLimit: limit,
		IPLimit:    limit,
		Config:     cfg,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !allowed {
		t.Fatalf("Check() allowed = false, want true")
	}
	if len(checker.calls) != 2 {
		t.Fatalf("rate limiter calls = %d, want 2", len(checker.calls))
	}
	if checker.calls[0].action != string(EmailAuthActionPasswordLogin)+":email" {
		t.Fatalf("email action = %q", checker.calls[0].action)
	}
	if checker.calls[1].action != string(EmailAuthActionPasswordLogin)+":ip" {
		t.Fatalf("ip action = %q", checker.calls[1].action)
	}
	for _, call := range checker.calls {
		if strings.Contains(call.userKey, "User@Example.COM") || strings.Contains(call.userKey, "203.0.113.10") {
			t.Fatalf("raw identifier leaked into rate limit key: %+v", call)
		}
	}
}

func TestEmailAuthLimitFailsClosed(t *testing.T) {
	checker := &recordingRateLimitChecker{err: errors.New("redis unavailable")}
	limiter := NewEmailAuthLimiter(checker)
	cfg := config.NewDefaultAuthServiceConfig()
	cfg.AppSecret = "limiter-secret"
	limit := config.RateLimit{MaxRequests: 5, WindowDuration: time.Minute}

	allowed, err := limiter.Check(context.Background(), EmailAuthLimitRequest{
		InstanceID: "tenant-a",
		Action:     EmailAuthActionPasswordLogin,
		Email:      "user@example.com",
		IP:         "203.0.113.10",
		EmailLimit: limit,
		IPLimit:    limit,
		Config:     cfg,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if allowed {
		t.Fatal("limiter should fail closed")
	}
}

type recordingRateLimitChecker struct {
	allowed []bool
	err     error
	calls   []rateLimitCall
}

type rateLimitCall struct {
	userKey string
	action  string
}

func (c *recordingRateLimitChecker) CheckAndRecordRequest(_ context.Context, userKey any, action, _ string, _ config.RateLimit, _ *config.AuthServiceConfig) (bool, error) {
	c.calls = append(c.calls, rateLimitCall{userKey: userKey.(string), action: action})
	if c.err != nil {
		return false, c.err
	}
	if len(c.allowed) == 0 {
		return true, nil
	}
	allowed := c.allowed[0]
	c.allowed = c.allowed[1:]
	return allowed, nil
}
