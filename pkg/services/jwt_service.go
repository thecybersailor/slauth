package services

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
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

// getPEMPreview returns a safe preview of PEM data for logging
func getPEMPreview(pemData string) string {
	if len(pemData) == 0 {
		return "<empty>"
	}
	// Show first 50 chars and last 20 chars, with length
	if len(pemData) <= 70 {
		return fmt.Sprintf("<%d chars: %s>", len(pemData), pemData)
	}
	return fmt.Sprintf("<%d chars: %s...%s>", len(pemData), pemData[:50], pemData[len(pemData)-20:])
}

// parsePrivateKey parses PEM private key based on algorithm
// Supports both SEC1 format ("EC PRIVATE KEY") and PKCS#8 format ("PRIVATE KEY")
func parsePrivateKey(pemData string, algorithm types.SignAlgorithm) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		slog.Error("[parsePrivateKey] Failed to decode PEM block", "algorithm", algorithm, "pemDataLen", len(pemData), "pemDataPreview", getPEMPreview(pemData))
		return nil, consts.BAD_JWT
	}

	switch algorithm {
	case types.SignAlgES256:
		// Try PKCS#8 format first (modern format, "PRIVATE KEY")
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			// Verify it's an EC key
			if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
				return ecKey, nil
			}
			slog.Error("[parsePrivateKey] PKCS#8 key is not an EC key", "keyType", fmt.Sprintf("%T", key))
		} else {
			slog.Warn("[parsePrivateKey] PKCS#8 parse failed, trying SEC1", "error", err)
		}
		// Fallback to SEC1 format (legacy format, "EC PRIVATE KEY")
		ecKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			slog.Error("[parsePrivateKey] SEC1 parse also failed", "error", err, "blockType", block.Type, "blockBytesLen", len(block.Bytes))
			return nil, consts.BAD_JWT
		}
		return ecKey, nil
	case types.SignAlgRS256:
		// Try PKCS#1 format first (traditional RSA format, "RSA PRIVATE KEY")
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		} else {
			slog.Warn("[parsePrivateKey] PKCS#1 parse failed, trying PKCS#8", "error", err)
		}
		// Fallback to PKCS#8 format (modern format, "PRIVATE KEY")
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			// Verify it's an RSA key
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				return rsaKey, nil
			}
			slog.Error("[parsePrivateKey] PKCS#8 key is not an RSA key", "keyType", fmt.Sprintf("%T", key))
		} else {
			slog.Error("[parsePrivateKey] PKCS#8 parse also failed", "error", err, "blockType", block.Type, "blockBytesLen", len(block.Bytes))
		}
		return nil, consts.BAD_JWT
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
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Entry", "userID", userID, "instanceId", instanceId, "sessionID", sessionID)
	secrets := j.getSecrets()
	if secrets == nil {
		slog.Error("[JWT GenerateAccessTokenWithExpiry] Secrets is nil")
		return "", 0, consts.BAD_JWT
	}
	if secrets.PrimaryKeyId == "" {
		slog.Error("[JWT GenerateAccessTokenWithExpiry] PrimaryKeyId is empty")
		return "", 0, consts.BAD_JWT
	}
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Got secrets", "primaryKeyId", secrets.PrimaryKeyId, "keysCount", len(secrets.Keys))

	primaryKey, exists := secrets.Keys[secrets.PrimaryKeyId]
	if !exists {
		availableKeys := make([]string, 0, len(secrets.Keys))
		for k := range secrets.Keys {
			availableKeys = append(availableKeys, k)
		}
		slog.Error("[JWT GenerateAccessTokenWithExpiry] PrimaryKey not found in Keys", "primaryKeyId", secrets.PrimaryKeyId, "availableKeys", availableKeys)
		return "", 0, consts.BAD_JWT
	}
	if primaryKey.PrivateKey == "" {
		slog.Error("[JWT GenerateAccessTokenWithExpiry] PrimaryKey.PrivateKey is empty", "primaryKeyId", secrets.PrimaryKeyId)
		return "", 0, consts.BAD_JWT
	}
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Got primaryKey", "algorithm", primaryKey.Algorithm, "privateKeyLen", len(primaryKey.PrivateKey))

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
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Claims created", "subject", claims.Subject, "issuer", claims.Issuer)

	signingMethod, err := getSigningMethod(primaryKey.Algorithm)
	if err != nil {
		slog.Error("[JWT GenerateAccessTokenWithExpiry] Failed to get signing method", "algorithm", primaryKey.Algorithm, "error", err)
		return "", 0, consts.BAD_JWT
	}
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Got signing method", "algorithm", primaryKey.Algorithm)
	token := jwt.NewWithClaims(signingMethod, claims)

	// Add kid to header
	token.Header["kid"] = secrets.PrimaryKeyId

	slog.Info("[JWT GenerateAccessTokenWithExpiry] Before parsePrivateKey")
	privateKey, err := parsePrivateKey(primaryKey.PrivateKey, primaryKey.Algorithm)
	if err != nil {
		slog.Error("[JWT GenerateAccessTokenWithExpiry] Failed to parse private key", "algorithm", primaryKey.Algorithm, "error", err)
		return "", 0, consts.BAD_JWT
	}
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Private key parsed successfully")

	slog.Info("[JWT GenerateAccessTokenWithExpiry] Before SignedString")
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		slog.Error("[JWT GenerateAccessTokenWithExpiry] Failed to sign token", "error", err)
		return "", 0, err
	}
	slog.Info("[JWT GenerateAccessTokenWithExpiry] Token signed successfully", "tokenLen", len(tokenString))

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
