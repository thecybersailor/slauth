package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/thecybersailor/slauth/pkg/types"
)

type MockProvider struct {
	clientID string
}

type MockOAuthConfig struct {
	ClientID string `json:"client_id"`
}

func NewMockProvider(config *MockOAuthConfig) types.IdentityProvider {
	return &MockProvider{
		clientID: config.ClientID,
	}
}

func (p *MockProvider) GetName() string {
	return "mock"
}

func (p *MockProvider) Authorize(_ json.RawMessage) (*types.OAuthConfig, error) {
	return &types.OAuthConfig{
		Config: map[string]any{
			"client_id": p.clientID,
		},
		FlowType: types.FlowTypeAuthCode,
	}, nil
}

type MockCredential struct {
	Code string `json:"code"`
}

func (p *MockProvider) ValidateCredential(ctx context.Context, credential json.RawMessage) (*types.OAuthResponse, error) {
	slog.Info("Mock ValidateCredential", "raw_credential", string(credential))

	var credData MockCredential
	if err := json.Unmarshal(credential, &credData); err != nil {
		slog.Error("Mock ValidateCredential - Unmarshal error", "error", err)
		return nil, fmt.Errorf("invalid credential format")
	}

	return nil, fmt.Errorf("mock OAuth should use ExchangeCodeForToken flow")
}

func (p *MockProvider) ExchangeCodeForToken(ctx context.Context, code string, redirectURI string) (*types.OAuthResponse, error) {
	slog.Info("Mock ExchangeCodeForToken",
		"clientID", p.clientID,
		"code", code,
		"redirectURI", redirectURI)

	userInfo := &types.ExternalUserInfo{
		UID:    fmt.Sprintf("mock-%s", code),
		Email:  fmt.Sprintf("mock-%s@example.com", code),
		Name:   fmt.Sprintf("Mock User %s", code),
		Avatar: "https://via.placeholder.com/150",
		Metadata: map[string]any{
			"provider": "mock",
			"code":     code,
		},
	}

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken:  fmt.Sprintf("mock_access_token_%s", code),
		RefreshToken: fmt.Sprintf("mock_refresh_token_%s", code),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}
