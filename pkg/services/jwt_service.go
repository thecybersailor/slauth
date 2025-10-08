package services

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/types"
)

// JWTClaims represents the JWT claims structure
type JWTClaims struct {
	jwt.RegisteredClaims
	UserID     string         `json:"user_id"`
	InstanceId string         `json:"instance_id"`
	Email      string         `json:"email,omitempty"`
	Phone      string         `json:"phone,omitempty"`
	Role       string         `json:"role,omitempty"`
	AAL        types.AALLevel `json:"aal"`
	AMR        []string       `json:"amr"` // Authentication Method Reference
	SessionID  uint           `json:"session_id"`
	UserMeta   map[string]any `json:"user_metadata,omitempty"`
	AppMeta    map[string]any `json:"app_metadata,omitempty"`
}

// JWTService handles JWT token operations
type JWTService struct {
	secretKey          []byte
	getAccessTokenTTL  func() time.Duration
	getRefreshTokenTTL func() time.Duration
	issuer             string
}

// NewJWTService creates a new JWT service
func NewJWTService(secretKey string, getAccessTokenTTL, getRefreshTokenTTL func() time.Duration, issuer string) *JWTService {
	return &JWTService{
		secretKey:          []byte(secretKey),
		getAccessTokenTTL:  getAccessTokenTTL,
		getRefreshTokenTTL: getRefreshTokenTTL,
		issuer:             issuer,
	}
}

// GenerateAccessToken generates a new access token
func (j *JWTService) GenerateAccessToken(userID string, instanceId, email, phone, role string, aal types.AALLevel, amr []string, sessionID uint, userMeta, appMeta map[string]any) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userID,
			Issuer:    j.issuer,
			Audience:  []string{instanceId},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.getAccessTokenTTL())),
		},
		UserID:     userID,
		InstanceId: instanceId,
		Email:      email,
		Phone:      phone,
		Role:       role,
		AAL:        aal,
		AMR:        amr,
		SessionID:  sessionID,
		UserMeta:   userMeta,
		AppMeta:    appMeta,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// GenerateAccessTokenWithExpiry generates a new access token and returns both token and expiry time
func (j *JWTService) GenerateAccessTokenWithExpiry(userID string, instanceId, email, phone, role string, aal types.AALLevel, amr []string, sessionID uint, userMeta, appMeta map[string]any) (string, int64, error) {
	now := time.Now()
	expiresAt := now.Add(j.getAccessTokenTTL())
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userID,
			Issuer:    j.issuer,
			Audience:  []string{instanceId},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		UserID:     userID,
		InstanceId: instanceId,
		Email:      email,
		Phone:      phone,
		Role:       role,
		AAL:        aal,
		AMR:        amr,
		SessionID:  sessionID,
		UserMeta:   userMeta,
		AppMeta:    appMeta,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", 0, err
	}

	// Return token and relative expiry time in seconds
	expiresIn := int64(expiresAt.Sub(now).Seconds())
	return tokenString, expiresIn, nil
}

// GenerateRefreshToken generates a new refresh token
func (j *JWTService) GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateAccessToken validates and parses an access token
func (j *JWTService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	slog.Info("JWT: Starting token parsing", "tokenLength", len(tokenString), "accessTokenTTL", j.getAccessTokenTTL())

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, consts.BAD_JWT
		}
		return j.secretKey, nil
	})

	if err != nil {
		slog.Warn("JWT: Token parsing failed", "error", err.Error())
		return nil, consts.BAD_JWT
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		now := time.Now()
		slog.Info("JWT: Token validation successful",
			"sessionID", claims.SessionID,
			"userID", claims.UserID,
			"issuedAt", claims.IssuedAt.Time,
			"expiresAt", claims.ExpiresAt.Time,
			"currentTime", now,
			"timeUntilExpiry", claims.ExpiresAt.Time.Sub(now).Seconds(),
		)
		return claims, nil
	}

	slog.Warn("JWT: Token claims invalid", "tokenValid", token.Valid)
	return nil, consts.BAD_JWT
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func ExtractTokenFromHeader(authHeader string) string {
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	return ""
}

// RefreshAccessToken generates a new access token using existing claims
func (j *JWTService) RefreshAccessToken(claims *JWTClaims) (string, error) {
	// Update timestamps
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(j.getAccessTokenTTL()))
	claims.ID = uuid.New().String() // New JTI

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}
