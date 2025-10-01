package cloudflare

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/flaboy/aira-core/pkg/httpc"
	"github.com/flaboy/pin/usererrors"
	"github.com/valyala/fasthttp"
)

type TurnstileCloudflare struct {
	CloudflareTurnstileKey string
}

func NewCaptchaProvider(secretKey string) *TurnstileCloudflare {
	return &TurnstileCloudflare{
		CloudflareTurnstileKey: secretKey,
	}
}

func (t *TurnstileCloudflare) ValidateCaptcha(ctx context.Context, captchaToken string) (bool, error) {
	if captchaToken == "" {
		return false, usererrors.New("turnstile response is empty")
	}

	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	args.Add("secret", t.CloudflareTurnstileKey)
	args.Add("response", captchaToken)

	responseBody, err := httpc.DoPostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", args)
	if err != nil {
		return false, err
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return false, err
	}

	if !result.Success {
		return false, errors.New("turnstile validation failed")
	}

	return true, nil
}
