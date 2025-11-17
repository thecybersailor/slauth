package google

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/types"
	"google.golang.org/api/idtoken"
)

type GoogleProvider struct {
	clientID      string
	clientSecret  string
	useEmailIdent bool
}

type GoogleOAuthConfig struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	UseEmailIdent bool   `json:"use_email_ident"` // Use email as UID instead of sub (default: false)
}

func NewGoogleProvider(config *GoogleOAuthConfig) types.IdentityProvider {
	return &GoogleProvider{
		clientID:      config.ClientID,
		clientSecret:  config.ClientSecret,
		useEmailIdent: config.UseEmailIdent,
	}
}

func (p *GoogleProvider) GetName() string {
	return "google"
}

func (p *GoogleProvider) Authorize(_ json.RawMessage) (*types.OAuthConfig, error) {
	return &types.OAuthConfig{
		Config: map[string]any{
			"client_id": p.clientID,
		},
		FlowType: types.FlowTypeAuthCode, // PKCE flow
	}, nil
}

// GoogleCredential represents the credential data from frontend
type GoogleCredential struct {
	Credential string `json:"credential"`
	ClientID   string `json:"client_id"`
}

func (p *GoogleProvider) ValidateCredential(ctx context.Context, credential json.RawMessage) (*types.OAuthResponse, error) {
	slog.Info("Google ValidateCredential", "raw_credential", string(credential))

	var credData GoogleCredential
	if err := json.Unmarshal(credential, &credData); err != nil {
		slog.Error("Google ValidateCredential - Unmarshal error", "error", err)
		return nil, consts.BAD_JSON
	}

	slog.Info("Google ValidateCredential - Parsed credential", "credential", credData)

	if credData.Credential == "" {
		return nil, consts.VALIDATION_FAILED
	}

	if credData.ClientID == "" {
		return nil, consts.VALIDATION_FAILED
	}

	payload, err := idtoken.Validate(ctx, credData.Credential, credData.ClientID)
	if err != nil {
		return nil, consts.BAD_JWT
	}

	if payload.Issuer != "https://accounts.google.com" {
		return nil, consts.BAD_JWT
	}

	if payload.Audience != credData.ClientID {
		return nil, consts.BAD_JWT
	}

	// Determine UID based on configuration
	uid := payload.Subject // Default: use Google's 'sub' (unique user ID)
	if p.useEmailIdent {
		uid = getString(payload.Claims, "email") // Use email for backward compatibility
		slog.Info("[Google OAuth] Using email as UID for backward compatibility",
			"email", uid,
			"sub", payload.Subject)
	} else {
		slog.Info("[Google OAuth] Using sub as UID",
			"sub", uid,
			"email", getString(payload.Claims, "email"))
	}

	userInfo := &types.ExternalUserInfo{
		UID:    uid,
		Name:   getString(payload.Claims, "name"),
		Avatar: getString(payload.Claims, "picture"),
		Locale: getString(payload.Claims, "locale"),
		Metadata: map[string]any{
			"given_name":  getString(payload.Claims, "given_name"),
			"family_name": getString(payload.Claims, "family_name"),
		},
	}

	if payload.Claims["email_verified"] == true {
		userInfo.Email = getString(payload.Claims, "email")
	}

	slog.Info("[Google OAuth] ValidateCredential completed",
		"uid", userInfo.UID,
		"email", userInfo.Email,
		"name", userInfo.Name)

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken: credData.Credential, // For Google, the credential is the ID token
		TokenType:   "Bearer",
		ExpiresIn:   3600, // Default expiration
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

func (p *GoogleProvider) ExchangeCodeForToken(ctx context.Context, code string, redirectURI string) (*types.OAuthResponse, error) {
	slog.Info("Google ExchangeCodeForToken",
		"clientID", p.clientID,
		"clientSecretSet", p.clientSecret != "",
		"code", code[:20]+"...",
		"redirectURI", redirectURI)

	if p.clientID == "" || p.clientSecret == "" {
		slog.Error("Google OAuth not configured properly",
			"clientIDEmpty", p.clientID == "",
			"clientSecretEmpty", p.clientSecret == "")
		return nil, consts.OAUTH_PROVIDER_NOT_SUPPORTED
	}

	// Prepare token exchange request
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURI)

	bodyData := data.Encode()
	slog.Info("Google token exchange request",
		"redirect_uri", redirectURI,
		"grant_type", data.Get("grant_type"),
		"bodyLength", len(bodyData))

	// Make HTTP request to Google
	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(bodyData))
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		return nil, consts.UNEXPECTED_FAILURE
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	slog.Info("Sending request to Google", "url", req.URL.String(), "contentLength", req.ContentLength)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Google token exchange HTTP request failed", "error", err, "errorType", fmt.Sprintf("%T", err))
		return nil, consts.UNEXPECTED_FAILURE
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Error("Failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		var errorBody map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorBody); err != nil {
			slog.Error("Google token exchange failed - cannot decode error body",
				"statusCode", resp.StatusCode,
				"error", err)
			return nil, consts.BAD_OAUTH_CALLBACK
		}
		slog.Error("Google token exchange failed",
			"statusCode", resp.StatusCode,
			"error", errorBody)
		return nil, consts.BAD_OAUTH_CALLBACK
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, consts.BAD_JSON
	}

	// Validate and parse ID token
	payload, err := idtoken.Validate(ctx, tokenResp.IDToken, p.clientID)
	if err != nil {
		return nil, consts.BAD_JWT
	}

	// Determine UID based on configuration
	uid := payload.Subject // Default: use Google's 'sub' (unique user ID)
	if p.useEmailIdent {
		uid = getString(payload.Claims, "email") // Use email for backward compatibility
		slog.Info("[Google OAuth] Using email as UID for backward compatibility",
			"email", uid,
			"sub", payload.Subject)
	} else {
		slog.Info("[Google OAuth] Using sub as UID",
			"sub", uid,
			"email", getString(payload.Claims, "email"))
	}

	// Extract user information from ID token
	userInfo := &types.ExternalUserInfo{
		UID:    uid,
		Name:   getString(payload.Claims, "name"),
		Avatar: getString(payload.Claims, "picture"),
		Locale: getString(payload.Claims, "locale"),
		Metadata: map[string]any{
			"given_name":  getString(payload.Claims, "given_name"),
			"family_name": getString(payload.Claims, "family_name"),
		},
	}

	if payload.Claims["email_verified"] == true {
		userInfo.Email = getString(payload.Claims, "email")
	}

	slog.Info("[Google OAuth] ExchangeCodeForToken completed",
		"uid", userInfo.UID,
		"email", userInfo.Email,
		"name", userInfo.Name)

	tokenInfo := &types.OAuthTokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}

	return &types.OAuthResponse{
		UserInfo:  userInfo,
		TokenInfo: tokenInfo,
	}, nil
}

func getString(claims map[string]any, key string) string {
	if value, ok := claims[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}
