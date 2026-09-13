package core

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggingFlowDoesNotExposeSecretsOnSuccess(t *testing.T) {
	var out bytes.Buffer
	restoreLogger := captureSlog(t, &out)
	defer restoreLogger()

	ctx := &Context[SigninData]{Data: SigninData{
		Password:     "test-password-marker",
		AccessToken:  "test-access-marker",
		RefreshToken: "test-refresh-marker",
	}}

	if err := LoggingFlow[SigninData]()(ctx, func() error { return nil }); err != nil {
		t.Fatal(err)
	}

	assertLogDoesNotContain(t, out.String(),
		"test-password-marker",
		"test-access-marker",
		"test-refresh-marker",
	)
	if !strings.Contains(out.String(), "duration") {
		t.Fatal("missing safe timing field")
	}
}

func TestLoggingFlowDoesNotExposeSecretsOnError(t *testing.T) {
	var out bytes.Buffer
	restoreLogger := captureSlog(t, &out)
	defer restoreLogger()

	ctx := &Context[PasswordChangeData]{Data: PasswordChangeData{
		CurrentPassword: "test-current-password-marker",
		NewPassword:     "test-new-password-marker",
	}}

	err := LoggingFlow[PasswordChangeData]()(ctx, func() error {
		return errors.New("forced failure")
	})
	if err == nil {
		t.Fatal("expected error")
	}

	assertLogDoesNotContain(t, out.String(),
		"test-current-password-marker",
		"test-new-password-marker",
	)
	if !strings.Contains(out.String(), "forced failure") {
		t.Fatal("missing error value")
	}
}

func captureSlog(t *testing.T, out *bytes.Buffer) func() {
	t.Helper()
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(out, nil)))
	return func() { slog.SetDefault(previous) }
}

func assertLogDoesNotContain(t *testing.T, logs string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Fatalf("secret %q was logged in %s", secret, logs)
		}
	}
}
