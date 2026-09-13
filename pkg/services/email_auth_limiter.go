package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/thecybersailor/slauth/pkg/config"
)

type EmailAuthAction string

const (
	EmailAuthActionPasswordLogin EmailAuthAction = "password_login"
)

type RateLimitChecker interface {
	CheckAndRecordRequest(ctx context.Context, userKey any, action, instanceId string, rateLimit config.RateLimit, cfg *config.AuthServiceConfig) (bool, error)
}

type EmailAuthLimiter struct {
	rateLimiter RateLimitChecker
}

type EmailAuthLimitRequest struct {
	InstanceID string
	Action     EmailAuthAction
	Email      string
	IP         string
	EmailLimit config.RateLimit
	IPLimit    config.RateLimit
	Config     *config.AuthServiceConfig
}

func NewEmailAuthLimiter(rateLimiter RateLimitChecker) *EmailAuthLimiter {
	return &EmailAuthLimiter{rateLimiter: rateLimiter}
}

func (l *EmailAuthLimiter) Check(ctx context.Context, req EmailAuthLimitRequest) (bool, error) {
	if l == nil || l.rateLimiter == nil {
		return true, nil
	}
	if req.Email != "" {
		allowed, err := l.rateLimiter.CheckAndRecordRequest(
			ctx,
			emailAuthDimensionKey(req.Config.AppSecret, req.InstanceID, "email", normalizeEmailAuthIdentifier(req.Email)),
			string(req.Action)+":email",
			req.InstanceID,
			req.EmailLimit,
			req.Config,
		)
		if err != nil || !allowed {
			return false, err
		}
	}
	if req.IP != "" {
		allowed, err := l.rateLimiter.CheckAndRecordRequest(
			ctx,
			emailAuthDimensionKey(req.Config.AppSecret, req.InstanceID, "ip", strings.TrimSpace(req.IP)),
			string(req.Action)+":ip",
			req.InstanceID,
			req.IPLimit,
			req.Config,
		)
		if err != nil || !allowed {
			return false, err
		}
	}
	return true, nil
}

func emailAuthDimensionKey(secret, instanceID, dimension, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, part := range []string{instanceID, dimension, value} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return dimension + ":" + hex.EncodeToString(mac.Sum(nil))
}

func normalizeEmailAuthIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
