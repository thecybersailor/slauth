package services_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type staticSecretsProvider struct {
	secrets *types.InstanceSecrets
}

func (p *staticSecretsProvider) GetSecrets(instanceId string) (*types.InstanceSecrets, error) {
	return p.secrets, nil
}

func TestRequestValidator_AllowsAnonymousForWebAuthnFactorEndpoints(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	db := openSQLiteMemoryDB(t)
	if err := db.AutoMigrate(&models.AuthInstance{}); err != nil {
		t.Fatalf("migrate auth_instances: %v", err)
	}

	authService := services.NewAuthServiceImpl(db, newTestSecretsProvider(t), "test-instance")

	router := gin.New()
	protected := router.Group("")
	protected.Use(authService.RequestValidator())
	protected.POST("/factors/challenge", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/factors/challenge", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() == "" {
		t.Fatalf("expected body, got empty")
	}
}
