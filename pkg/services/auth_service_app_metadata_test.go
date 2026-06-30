package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCreateAndRefreshSessionIncludeAppMetadataInAccessToken(t *testing.T) {
	db := newAppMetadataTokenTestDB(t)
	service := NewAuthServiceImpl(db, newAppMetadataTokenTestSecretsProvider(t), "web_user")
	phone := "+8618616977030"
	user, err := service.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
		Phone:       &phone,
		AppMetadata: map[string]any{"is_admin": true},
	}, UserCreatedSourceAdmin, nil, nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	session, accessToken, _, _, err := service.CreateSession(context.Background(), user, types.AALLevel1, []string{"sms"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	assertAccessTokenAdminAppMetadata(t, accessToken)

	_, refreshedAccessToken, _, _, err := service.RefreshSession(context.Background(), user, session.ID, types.AALLevel1, []string{"refresh_token"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}
	assertAccessTokenAdminAppMetadata(t, refreshedAccessToken)
}

func assertAccessTokenAdminAppMetadata(t *testing.T, token string) {
	t.Helper()
	var parser jwt.Parser
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	appMetadata, ok := claims["app_metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("app_metadata missing from claims: %#v", claims["app_metadata"])
	}
	if appMetadata["is_admin"] != true {
		t.Fatalf("expected app_metadata.is_admin true, got %#v", appMetadata["is_admin"])
	}
}

func newAppMetadataTokenTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/slauth-app-metadata-token.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

func newAppMetadataTokenTestSecretsProvider(t *testing.T) *StaticSecretsProvider {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
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
	return NewStaticSecretsProvider(&types.InstanceSecrets{
		PrimaryKeyId: "app-metadata-test-key",
		AppSecret:    "app-metadata-token-test-secret",
		Keys: map[string]*types.SigningKey{
			"app-metadata-test-key": {
				Kid:        "app-metadata-test-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: string(privatePEM),
				PublicKey:  string(publicPEM),
			},
		},
	})
}
