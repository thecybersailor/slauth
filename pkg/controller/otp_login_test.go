package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	authconfig "github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPhoneOTPVerifyCreatesSlauthSession(t *testing.T) {
	router, db, authService := newPhoneOTPTestRouter(t)
	phone := "+8618616977030"

	sessionCode, token := storePhoneOTP(t, authService, phone)
	first := verifyPhoneOTP(t, router, phone, sessionCode, token)

	if first.User == nil {
		t.Fatalf("verify response missing user")
	}
	if first.Session == nil {
		t.Fatalf("verify response missing session")
	}
	if first.Session.AccessToken == "" || first.Session.RefreshToken == "" {
		t.Fatalf("verify response missing tokens: %+v", first.Session)
	}

	if first.User.UserMetadata["profile_key"] != "profile_value" {
		t.Fatalf("slauth should persist opaque verify metadata, got %+v", first.User.UserMetadata)
	}
	if _, ok := first.User.UserMetadata["display_name"]; ok {
		t.Fatalf("slauth should not create account display_name metadata: %+v", first.User.UserMetadata)
	}
	if _, ok := first.User.UserMetadata["name"]; ok {
		t.Fatalf("slauth should not create account name metadata: %+v", first.User.UserMetadata)
	}

	var saved models.User
	if err := db.Where("phone = ?", phone).First(&saved).Error; err != nil {
		t.Fatalf("load saved user: %v", err)
	}
	if saved.Username != nil {
		t.Fatalf("slauth phone otp user should not get an account display username, got %#v", *saved.Username)
	}

	claims := parseJWTClaims(t, first.Session.AccessToken)
	if claims["phone"] != phone {
		t.Fatalf("jwt phone claim = %v, want %s", claims["phone"], phone)
	}
	if _, ok := claims["name"]; ok {
		t.Fatalf("slauth jwt should not include account name claim: %#v", claims["name"])
	}
	if _, ok := claims["display_name"]; ok {
		t.Fatalf("slauth jwt should not include account display_name claim: %#v", claims["display_name"])
	}
	userMeta, ok := claims["user_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("jwt should include opaque user_metadata")
	}
	if userMeta["profile_key"] != "profile_value" {
		t.Fatalf("jwt user_metadata.profile_key = %#v, want profile_value", userMeta["profile_key"])
	}
	if _, exists := userMeta["display_name"]; exists {
		t.Fatalf("slauth jwt should not create user_metadata.display_name: %#v", userMeta)
	}
	if _, exists := userMeta["name"]; exists {
		t.Fatalf("slauth jwt should not create user_metadata.name: %#v", userMeta)
	}

	secondSessionCode, secondToken := storePhoneOTP(t, authService, phone)
	second := verifyPhoneOTP(t, router, phone, secondSessionCode, secondToken)
	if second.User == nil {
		t.Fatalf("second verify response missing user")
	}
	if second.User.ID != first.User.ID {
		t.Fatalf("second login should reuse user id, got %q want %q", second.User.ID, first.User.ID)
	}
	var count int64
	if err := db.Model(&models.User{}).Where("phone = ?", phone).Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one user for phone, got %d", count)
	}
}

func newPhoneOTPTestRouter(t *testing.T) (*gin.Engine, *gorm.DB, *services.AuthServiceImpl) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate models: %v", err)
	}
	cfg := authconfig.NewDefaultAuthServiceConfig()
	cfg.RatelimitConfig.TokenVerificationRateLimit.MaxRequests = 0
	if err := db.Create(&models.AuthInstance{InstanceId: "web_user", ConfigData: cfg}).Error; err != nil {
		t.Fatalf("create auth instance config: %v", err)
	}

	secrets := newPhoneOTPTestSecrets(t)
	authService := services.NewAuthServiceImpl(db, services.NewStaticSecretsProvider(secrets), "web_user")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterRoutes(router.Group("/auth/v1"), authService)
	return router, db, authService
}

func storePhoneOTP(t *testing.T, authService *services.AuthServiceImpl, phone string) (string, string) {
	t.Helper()

	code := "123456"
	sessionCode, err := authService.GetOTPService().StoreOTP(
		t.Context(), "", phone, code, types.OneTimeTokenTypeConfirmation, authService.GetInstanceId(), authService.GetDB(),
	)
	if err != nil {
		t.Fatalf("store otp: %v", err)
	}
	return sessionCode, code
}

func verifyPhoneOTP(t *testing.T, router *gin.Engine, phone, sessionCode, token string) AuthData {
	t.Helper()

	response := doJSONRequest(t, router, http.MethodPost, "/auth/v1/verify", map[string]any{
		"phone":        phone,
		"token":        token,
		"session_code": sessionCode,
		"type":         "sms",
		"options": map[string]any{
			"data": map[string]any{
				"profile_key": "profile_value",
			},
		},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data AuthData `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if envelope.Data.User != nil || envelope.Data.Session != nil {
		return envelope.Data
	}
	var direct AuthData
	if err := json.Unmarshal(response.Body.Bytes(), &direct); err != nil {
		t.Fatalf("decode direct verify response: %v", err)
	}
	return direct
}

func doJSONRequest(t *testing.T, router *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func parseJWTClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()

	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected jwt claims type %T", parsed.Claims)
	}
	return claims
}

func newPhoneOTPTestSecrets(t *testing.T) *types.InstanceSecrets {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return &types.InstanceSecrets{
		PrimaryKeyId: "test-key",
		Keys: map[string]*types.SigningKey{
			"test-key": {
				Kid:        "test-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: string(privatePEM),
				PublicKey:  string(publicPEM),
			},
		},
		AppSecret: "phone-otp-test-app-secret",
	}
}
