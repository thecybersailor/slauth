package services

import (
	"context"
	"crypto/md5"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/flaboy/aira-core/pkg/redis"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/thecybersailor/slauth/pkg/config"
)

type RateLimitService struct {
	appSecret string
}

func NewRateLimitService(appSecret string) *RateLimitService {
	return &RateLimitService{
		appSecret: appSecret,
	}
}

func (s *RateLimitService) generateKey(userID uint, action, domainCode string) string {

	appSecretHash := fmt.Sprintf("%x", md5.Sum([]byte(s.appSecret)))[:8]
	return fmt.Sprintf("rate_limit:%s:%s:%d:%s", appSecretHash, domainCode, userID, action)
}

func (s *RateLimitService) CheckRateLimit(ctx context.Context, userID uint, action, domainCode string, rateLimit config.RateLimit) (bool, error) {
	key := s.generateKey(userID, action, domainCode)

	now := time.Now()
	windowStart := now.Add(-rateLimit.WindowDuration)

	count, err := redis.RedisClient.ZCount(ctx, key,
		strconv.FormatInt(windowStart.UnixNano(), 10),
		strconv.FormatInt(now.UnixNano(), 10)).Result()

	if err != nil && err != redis.Nil {
		slog.Error("RateLimit: Failed to count requests", "error", err, "userID", userID, "action", action)
		return false, err
	}

	allowed := count < int64(rateLimit.MaxRequests)

	slog.Info("RateLimit: Check result",
		"userID", userID,
		"action", action,
		"currentCount", count,
		"maxRequests", rateLimit.MaxRequests,
		"windowDuration", rateLimit.WindowDuration,
		"windowStart", windowStart,
		"allowed", allowed)

	return allowed, nil
}

func (s *RateLimitService) RecordRequest(ctx context.Context, userID uint, action, domainCode string) error {
	key := s.generateKey(userID, action, domainCode)
	now := time.Now()

	err := redis.RedisClient.ZAdd(ctx, key, redisv9.Z{
		Score:  float64(now.UnixNano()),
		Member: now.Format(time.RFC3339Nano),
	}).Err()

	if err != nil {
		slog.Error("RateLimit: Failed to record request", "error", err, "userID", userID, "action", action)
		return err
	}

	expiry := time.Hour
	redis.RedisClient.Expire(ctx, key, expiry)

	slog.Info("RateLimit: Request recorded", "userID", userID, "action", action)
	return nil
}

func (s *RateLimitService) CleanupOldRecords(ctx context.Context, maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)

	pattern := "rate_limit:*"
	keys, err := redis.RedisClient.Keys(ctx, pattern).Result()
	if err != nil {
		slog.Error("RateLimit: Failed to get keys", "error", err)
		return err
	}

	deletedCount := 0
	for _, key := range keys {

		removed, err := redis.RedisClient.ZRemRangeByScore(ctx, key,
			"0", strconv.FormatInt(cutoff.UnixNano(), 10)).Result()
		if err != nil {
			slog.Warn("RateLimit: Failed to cleanup key", "key", key, "error", err)
			continue
		}
		deletedCount += int(removed)
	}

	slog.Info("RateLimit: Cleaned up old records", "deletedCount", deletedCount, "cutoff", cutoff)
	return nil
}

func (s *RateLimitService) GetRequestCount(ctx context.Context, userID uint, action, domainCode string, windowDuration time.Duration) (int64, error) {
	key := s.generateKey(userID, action, domainCode)
	now := time.Now()
	windowStart := now.Add(-windowDuration)

	count, err := redis.RedisClient.ZCount(ctx, key,
		strconv.FormatInt(windowStart.UnixNano(), 10),
		strconv.FormatInt(now.UnixNano(), 10)).Result()

	if err != nil && err != redis.Nil {
		return 0, err
	}

	return count, nil
}

func (s *RateLimitService) CheckAndRecordRequest(ctx context.Context, userID uint, action, domainCode string, rateLimit config.RateLimit) (bool, error) {
	key := s.generateKey(userID, action, domainCode)
	now := time.Now()
	windowStart := now.Add(-rateLimit.WindowDuration)

	luaScript := `
		local key = KEYS[1]
		local window_start = ARGV[1]
		local now = ARGV[2]
		local max_requests = tonumber(ARGV[3])
		local member = ARGV[4]
		local expiry = tonumber(ARGV[5])

		redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

		local count = redis.call('ZCARD', key)

		if count < max_requests then
			redis.call('ZADD', key, now, member)
			redis.call('EXPIRE', key, expiry)
			return 1
		else
			return 0
		end
	`

	result, err := redis.RedisClient.Eval(ctx, luaScript, []string{key},
		strconv.FormatInt(windowStart.UnixNano(), 10),
		strconv.FormatInt(now.UnixNano(), 10),
		strconv.Itoa(rateLimit.MaxRequests),
		now.Format(time.RFC3339Nano),
		int(time.Hour.Seconds()),
	).Result()

	if err != nil {
		slog.Error("RateLimit: Lua script failed", "error", err, "userID", userID, "action", action)
		return false, err
	}

	allowed := result.(int64) == 1

	slog.Info("RateLimit: Atomic check and record result",
		"userID", userID,
		"action", action,
		"maxRequests", rateLimit.MaxRequests,
		"windowDuration", rateLimit.WindowDuration,
		"allowed", allowed)

	return allowed, nil
}

func (s *RateLimitService) EnsureTableExists(ctx context.Context) error {

	return nil
}
