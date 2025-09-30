package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/mail"
	"strconv"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// convertUserToResponse converts a models.User to controller.User response format
func convertUserToResponse(user *models.User) *User {
	if user == nil {
		return nil
	}

	// Generate hashid for user ID
	userHashID, err := services.GenerateUserHashID(user.ID)
	if err != nil {
		// Fallback to raw ID if hashid generation fails
		userHashID = strconv.FormatUint(uint64(user.ID), 10)
	}

	userResp := &User{
		ID:           userHashID,
		Aud:          user.DomainCode,
		CreatedAt:    formatTime(&user.CreatedAt),
		UpdatedAt:    formatTime(&user.UpdatedAt),
		ConfirmedAt:  formatTime(user.ConfirmedAt),
		LastSignInAt: formatTime(user.LastSignInAt),
		IsAnonymous:  user.IsAnonymous,
		UserMetadata: make(map[string]any),
		AppMetadata:  make(map[string]any),
	}

	// Handle email
	if user.Email != nil {
		userResp.Email = *user.Email
		userResp.EmailConfirmedAt = formatTime(user.EmailConfirmedAt)
	}

	// Handle phone
	if user.Phone != nil {
		userResp.Phone = *user.Phone
		userResp.PhoneConfirmedAt = formatTime(user.PhoneConfirmedAt)
	}

	// Parse user metadata
	if user.RawUserMetaData != nil {
		var userMetadata map[string]any
		if err := json.Unmarshal(*user.RawUserMetaData, &userMetadata); err == nil {
			userResp.UserMetadata = userMetadata
		}
	}

	// Parse app metadata
	if user.RawAppMetaData != nil {
		var appMetadata map[string]any
		if err := json.Unmarshal(*user.RawAppMetaData, &appMetadata); err == nil {
			userResp.AppMetadata = appMetadata
		}
	}

	// Convert identities
	if len(user.Identities) > 0 {
		userResp.Identities = make([]UserIdentity, len(user.Identities))
		for i, identity := range user.Identities {
			userResp.Identities[i] = convertIdentityToResponse(&identity)
		}
	}

	// Convert MFA factors
	if len(user.MFAFactors) > 0 {
		userResp.Factors = make([]Factor, len(user.MFAFactors))
		for i, factor := range user.MFAFactors {
			userResp.Factors[i] = convertFactorToResponse(&factor)
		}
	}

	return userResp
}

// convertIdentityToResponse converts a models.Identity to controller.UserIdentity
func convertIdentityToResponse(identity *models.Identity) UserIdentity {
	return UserIdentity{
		ID:           strconv.FormatUint(uint64(identity.ID), 10),
		UserID:       strconv.FormatUint(uint64(identity.UserID), 10),
		IdentityID:   identity.ProviderID,
		Provider:     identity.Provider,
		CreatedAt:    formatTime(&identity.CreatedAt),
		LastSignInAt: formatTime(identity.LastSignInAt),
		UpdatedAt:    formatTime(&identity.UpdatedAt),
		IdentityData: make(map[string]any), // TODO: Parse identity data JSON
	}
}

// convertFactorToResponse converts a models.MFAFactor to controller.Factor
func convertFactorToResponse(factor *models.MFAFactor) Factor {
	friendlyName := ""
	if factor.FriendlyName != nil {
		friendlyName = *factor.FriendlyName
	}

	return Factor{
		ID:           strconv.FormatUint(uint64(factor.ID), 10),
		FriendlyName: friendlyName,
		FactorType:   factor.FactorType,
		Status:       factor.Status,
		CreatedAt:    formatTime(&factor.CreatedAt),
		UpdatedAt:    formatTime(&factor.UpdatedAt),
	}
}

// formatTime formats a time pointer to string, returns empty string if nil
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// extractUserIDFromToken extracts user ID from JWT claims
func extractUserIDFromToken(claims map[string]any) (string, error) {
	sub, ok := claims["sub"]
	if !ok {
		return "", consts.BAD_JWT
	}

	// sub claim now contains hashid directly
	userID, ok := sub.(string)
	if !ok {
		return "", consts.BAD_JWT
	}

	return userID, nil
}

// validateEmailOrPhone validates that at least one of email or phone is provided
func validateEmailOrPhone(email, phone string) bool {
	return email != "" || phone != ""
}

// extractBearerToken extracts Bearer token from Authorization header
func extractBearerToken(authHeader string) string {
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

// validateSignInRequest validates sign in request
func validateSignInRequest(req *SignInWithPasswordRequest) error {
	if !validateEmailOrPhone(req.Email, req.Phone) {
		return consts.VALIDATION_FAILED
	}

	if req.Password == "" {
		return consts.VALIDATION_FAILED
	}

	// Validate email format if email is provided
	if req.Email != "" {
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return consts.EMAIL_ADDRESS_INVALID
		}
	}

	return nil
}

// ===== OAuth Helper Functions =====

// generateCodeVerifier generates a PKCE code verifier
func generateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateCodeChallenge generates a PKCE code challenge from verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateSecureState generates a secure state parameter
func generateSecureState() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// getIdentityProvider gets an identity provider from AuthService
func getIdentityProvider(authService services.AuthService, providerName string) (types.IdentityProvider, bool) {
	return authService.GetIdentityProvider(providerName)
}

// OAuthUserInfo represents user info from OAuth provider
type OAuthUserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture,omitempty"`
	Verified bool   `json:"verified"`
}

// findOrCreateUserFromOAuth finds existing user or creates new one from OAuth data
func (a *AuthController) findOrCreateUserFromOAuth(ctx context.Context, userInfo *OAuthUserInfo, provider string) (*services.User, error) {
	// Try to find existing user by email
	if userInfo.Email != "" {
		user, err := a.authService.GetUserService().GetByEmail(ctx, userInfo.Email)
		if err == nil {
			// User exists, link this OAuth identity if not already linked
			// TODO: Check if identity already exists and link if needed
			return user, nil
		}
	}

	// Create new user
	userData := map[string]any{
		"name":     userInfo.Name,
		"picture":  userInfo.Picture,
		"provider": provider,
	}

	user, err := a.authService.GetUserService().CreateWithMetadata(ctx, userInfo.Email, "", "", userData, nil)
	if err != nil {
		return nil, err
	}

	// TODO: Create identity record linking user to OAuth provider

	return user, nil
}
