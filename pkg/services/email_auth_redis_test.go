package services

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	airaRedis "github.com/flaboy/aira-core/pkg/redis"
	"github.com/google/uuid"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/thecybersailor/slauth/pkg/config"
)

func TestEmailAuthRedisAtomicLimitAllowsExactlyN(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv("SLAUTH_EMAIL_AUTH_REDIS_ADDR"))
	if addr == "" {
		t.Skip("SLAUTH_EMAIL_AUTH_REDIS_ADDR is not set; skipping real Redis email auth limiter test")
	}
	client := redisv9.NewClient(&redisv9.Options{Addr: addr, Password: os.Getenv("SLAUTH_EMAIL_AUTH_REDIS_PASSWORD")})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	previous := airaRedis.RedisClient
	airaRedis.RedisClient = client
	t.Cleanup(func() {
		airaRedis.RedisClient = previous
		_ = client.Close()
	})

	cfg := config.NewDefaultAuthServiceConfig()
	cfg.AppSecret = "redis-email-auth-" + uuid.NewString()
	cfg.SetUpdatedAt(time.Unix(1700000000, 0))
	limit := config.RateLimit{MaxRequests: 5, WindowDuration: time.Minute}
	service := NewRateLimitService(cfg.AppSecret)
	userKey := "redis-user-" + uuid.NewString()
	instanceID := "redis_email_auth_" + strings.ReplaceAll(uuid.NewString(), "-", "_")
	action := "password_login:email"

	const attempts = 15
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := service.CheckAndRecordRequest(ctx, userKey, action, instanceID, limit, cfg)
			if err != nil {
				t.Errorf("check and record: %v", err)
				return
			}
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if allowed != limit.MaxRequests {
		t.Fatalf("allowed = %d, want %d", allowed, limit.MaxRequests)
	}
	if err := service.ClearUserActionRateLimit(ctx, userKey, action, instanceID, cfg); err != nil {
		t.Fatalf("cleanup redis key: %v", err)
	}
}
