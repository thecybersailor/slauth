package controller

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
)

func TestIDTokenLoggingDoesNotExposeCredential(t *testing.T) {
	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	router, _, _ := newPhoneOTPTestRouter(t)

	credential := "test-google-credential-marker"
	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=id_token", map[string]any{
		"provider":   "google",
		"credential": credential,
	})
	_ = resp
	if strings.Contains(out.String(), credential) {
		t.Fatalf("credential was logged in %s", out.String())
	}
	if !strings.Contains(out.String(), "google") {
		t.Fatalf("expected provider name in log, got %s", out.String())
	}
}

func TestPasswordSigninLoggingDoesNotExposeIssuedTokens(t *testing.T) {
	router, db, authService := newPhoneOTPTestRouter(t)
	password := "correct horse battery staple 2026"
	hash, err := authService.GetPasswordService().HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	email := "log-safe-login@example.com"
	now := time.Now()
	if err := db.Create(&models.User{
		InstanceId:        authService.GetInstanceId(),
		Email:             &email,
		EncryptedPassword: &hash,
		EmailConfirmedAt:  &now,
		ConfirmedAt:       &now,
		RawUserMetaData:   &models.JSON{},
		RawAppMetaData:    &models.JSON{},
	}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	var out bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{
		"email":    email,
		"password": password,
	})
	var envelope struct {
		Data AuthData `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if envelope.Data.Session == nil || envelope.Data.Session.AccessToken == "" || envelope.Data.Session.RefreshToken == "" {
		t.Fatalf("login missing tokens: %s", resp.Body.String())
	}
	assertLogDoesNotContain(t, out.String(), envelope.Data.Session.AccessToken, envelope.Data.Session.RefreshToken)
}

func assertLogDoesNotContain(t *testing.T, logs string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Fatalf("secret was logged in %s", logs)
		}
	}
}
