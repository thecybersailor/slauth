package facebook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/types"
)

type FacebookProvider struct{}

type FacebookUserDetails struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

func NewFacebookProvider() types.IdentityProvider {
	return &FacebookProvider{}
}

func (p *FacebookProvider) GetName() string {
	return "facebook"
}

func (p *FacebookProvider) Authorize(options json.RawMessage) (*types.OAuthConfig, error) {
	return nil, nil
}

func (p *FacebookProvider) ValidateCredential(ctx context.Context, credential json.RawMessage) (*types.OAuthResponse, error) {
	var credData map[string]string
	if err := json.Unmarshal(credential, &credData); err != nil {
		return nil, fmt.Errorf("invalid credential format: %w", err)
	}

	accessToken, ok := credData["accessToken"]
	if !ok {
		return nil, fmt.Errorf("missing accessToken field")
	}

	userDetails, err := p.fetchUserDetails(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Facebook user details: %w", err)
	}

	userInfo := &types.ExternalUserInfo{
		UID:    userDetails.ID,
		Email:  userDetails.Email,
		Name:   userDetails.Name,
		Avatar: userDetails.Picture.Data.URL,
		Metadata: map[string]any{
			"provider": "facebook",
		},
	}

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // Default expiration
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

func (p *FacebookProvider) ExchangeCodeForToken(ctx context.Context, code string, redirectURI string) (*types.OAuthResponse, error) {
	return nil, fmt.Errorf("facebook OAuth should be handled entirely by frontend")
}

func (p *FacebookProvider) fetchUserDetails(ctx context.Context, accessToken string) (*FacebookUserDetails, error) {
	url := fmt.Sprintf("https://graph.facebook.com/me?fields=id,name,email,picture&access_token=%s", accessToken)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook API returned status %d", resp.StatusCode)
	}

	var userDetails FacebookUserDetails
	if err := json.NewDecoder(resp.Body).Decode(&userDetails); err != nil {
		return nil, err
	}

	return &userDetails, nil
}
