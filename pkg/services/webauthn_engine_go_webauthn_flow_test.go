package services_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thecybersailor/slauth/pkg/services"
)

func TestGoWebAuthnEngine_BeginLogin_ReturnsOptionsAndSession(t *testing.T) {
	t.Parallel()

	engine, err := services.NewGoWebAuthnEngine(services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewGoWebAuthnEngine error: %v", err)
	}

	opts, session, err := engine.BeginLogin(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, services.WebAuthnUser{ID: []byte("user-1"), Name: "u", DisplayName: "u"}, [][]byte{[]byte("cred-1")})
	if err != nil {
		t.Fatalf("BeginLogin error: %v", err)
	}
	if len(opts) == 0 || len(session) == 0 {
		t.Fatalf("expected non-empty opts/session")
	}

	var sessionObj map[string]any
	if err := json.Unmarshal(session, &sessionObj); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	if sessionObj["challenge"] == nil {
		t.Fatalf("expected session.challenge")
	}
}

func TestGoWebAuthnEngine_BeginRegistration_ReturnsOptionsAndSession(t *testing.T) {
	t.Parallel()

	engine, err := services.NewGoWebAuthnEngine(services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewGoWebAuthnEngine error: %v", err)
	}

	opts, session, err := engine.BeginRegistration(context.Background(), services.WebAuthnRPConfig{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}, services.WebAuthnUser{ID: []byte("user-1"), Name: "u", DisplayName: "u"}, nil)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}
	if len(opts) == 0 || len(session) == 0 {
		t.Fatalf("expected non-empty opts/session")
	}
}
