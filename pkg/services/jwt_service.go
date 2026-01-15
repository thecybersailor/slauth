package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
	getSecrets         func() *types.InstanceSecrets
	getAccessTokenTTL  func() time.Duration
	getRefreshTokenTTL func() time.Duration
	issuer             string
}

// parsePrivateKey parses PEM private key based on algorithm
func parsePrivateKey(pemData string, algorithm types.SignAlgorithm) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, consts.BAD_JWT
	}

	switch algorithm {
	case types.SignAlgES256:
		return x509.ParseECPrivateKey(block.Bytes)
	case types.SignAlgRS256:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, consts.BAD_JWT
	}
}

// parsePublicKey parses PEM public key based on algorithm
func parsePublicKey(pemData string, algorithm types.SignAlgorithm) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, consts.BAD_JWT
	}

	switch algorithm {
	case types.SignAlgES256:
		return x509.ParsePKIXPublicKey(block.Bytes)
	case types.SignAlgRS256:
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, consts.BAD_JWT
	}
}

// getSigningMethod returns the signing method for the algorithm
func getSigningMethod(algorithm types.SignAlgorithm) (jwt.SigningMethod, error) {
	switch algorithm {
	case types.SignAlgES256:
		return jwt.SigningMethodES256, nil
	case types.SignAlgRS256:
		return jwt.SigningMethodRS256, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}
}

// NewJWTService creates a new JWT service
func NewJWTService(getSecrets func() *types.InstanceSecrets, getAccessTokenTTL, getRefreshTokenTTL func() time.Duration, issuer string) *JWTService {
	return &JWTService{
		getSecrets:         getSecrets,
		getAccessTokenTTL:  getAccessTokenTTL,
		getRefreshTokenTTL: getRefreshTokenTTL,
		issuer:             issuer,
	}
}

// GenerateAccessToken generates a new access token
func (j *JWTService) GenerateAccessToken(userID string, instanceId, email, phone, role string, aal types.AALLevel, amr []string, sessionID uint, userMeta, appMeta map[string]any) (string, error) {
	secrets := j.getSecrets()
	if secrets == nil || secrets.PrimaryKeyId == "" {
		return "", consts.BAD_JWT
	}

	primaryKey, exists := secrets.Keys[secrets.PrimaryKeyId]
	if !exists || primaryKey.PrivateKey == "" {
		return "", consts.BAD_JWT
	}

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

	signingMethod, err := getSigningMethod(primaryKey.Algorithm)
	if err != nil {
		return "", consts.BAD_JWT
	}
	token := jwt.NewWithClaims(signingMethod, claims)

	// Add kid to header
	token.Header["kid"] = secrets.PrimaryKeyId

	privateKey, err := parsePrivateKey(primaryKey.PrivateKey, primaryKey.Algorithm)
	if err != nil {
		return "", consts.BAD_JWT
	}

	return token.SignedString(privateKey)
}

// GenerateAccessTokenWithExpiry generates a new access token and returns both token and expiry time
func (j *JWTService) GenerateAccessTokenWithExpiry(userID string, instanceId, email, phone, role string, aal types.AALLevel, amr []string, sessionID uint, userMeta, appMeta map[string]any) (string, int64, error) {
	secrets := j.getSecrets()
	if secrets == nil || secrets.PrimaryKeyId == "" {
		return "", 0, consts.BAD_JWT
	}

	primaryKey, exists := secrets.Keys[secrets.PrimaryKeyId]
	if !exists || primaryKey.PrivateKey == "" {
		return "", 0, consts.BAD_JWT
	}

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

	signingMethod, err := getSigningMethod(primaryKey.Algorithm)
	if err != nil {
		return "", 0, consts.BAD_JWT
	}
	token := jwt.NewWithClaims(signingMethod, claims)

	// Add kid to header
	token.Header["kid"] = secrets.PrimaryKeyId

	privateKey, err := parsePrivateKey(primaryKey.PrivateKey, primaryKey.Algorithm)
	if err != nil {
		return "", 0, consts.BAD_JWT
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", 0, err
	}

	// Return token and absolute expiry timestamp
	return tokenString, expiresAt.Unix(), nil
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
		// Extract kid from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			slog.Warn("JWT: Missing kid in token header")
			return nil, consts.BAD_JWT
		}

		secrets := j.getSecrets()
		if secrets == nil || secrets.Keys == nil {
			slog.Warn("JWT: No secrets available")
			return nil, consts.BAD_JWT
		}

		key, exists := secrets.Keys[kid]
		if !exists {
			slog.Warn("JWT: Unknown kid", "kid", kid)
			return nil, consts.BAD_JWT
		}

		publicKey, err := parsePublicKey(key.PublicKey, key.Algorithm)
		if err != nil {
			slog.Warn("JWT: Failed to parse public key", "kid", kid, "error", err)
			return nil, consts.BAD_JWT
		}

		// Validate signing method matches the key algorithm
		expectedMethod, err := getSigningMethod(key.Algorithm)
		if err != nil {
			slog.Warn("JWT: Unsupported algorithm", "kid", kid, "algorithm", key.Algorithm)
			return nil, consts.BAD_JWT
		}
		if token.Method.Alg() != expectedMethod.Alg() {
			slog.Warn("JWT: Algorithm mismatch", "expected", expectedMethod.Alg(), "got", token.Method.Alg())
			return nil, consts.BAD_JWT
		}

		return publicKey, nil
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
	secrets := j.getSecrets()
	if secrets == nil || secrets.PrimaryKeyId == "" {
		return "", consts.BAD_JWT
	}

	primaryKey, exists := secrets.Keys[secrets.PrimaryKeyId]
	if !exists || primaryKey.PrivateKey == "" {
		return "", consts.BAD_JWT
	}

	// Update timestamps
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(j.getAccessTokenTTL()))
	claims.ID = uuid.New().String() // New JTI

	signingMethod, err := getSigningMethod(primaryKey.Algorithm)
	if err != nil {
		return "", consts.BAD_JWT
	}
	token := jwt.NewWithClaims(signingMethod, claims)

	// Add kid to header
	token.Header["kid"] = secrets.PrimaryKeyId

	privateKey, err := parsePrivateKey(primaryKey.PrivateKey, primaryKey.Algorithm)
	if err != nil {
		return "", consts.BAD_JWT
	}

	return token.SignedString(privateKey)
}
