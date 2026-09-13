package controller

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
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
