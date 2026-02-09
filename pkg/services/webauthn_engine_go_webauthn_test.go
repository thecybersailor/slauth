package services_test

import (
	"testing"

	"github.com/thecybersailor/slauth/pkg/services"
)

func TestNewGoWebAuthnEngine_ReturnsEngine(t *testing.T) {
	t.Parallel()

	engine, err := services.NewGoWebAuthnEngine(services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if engine == nil {
		t.Fatalf("expected engine, got nil")
	}
}
