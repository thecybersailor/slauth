package services

import (
	"strings"
	"testing"

	"github.com/thecybersailor/slauth/pkg/types"
)

func TestEmailActionURLContainsOnlyOperationToken(t *testing.T) {
	got, err := emailActionURL("https://account.example.com/ignored?redirect=https://evil.example", types.EmailActionPurposeRecovery, "id.secret")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	if got != "https://account.example.com/reset-password#token=id.secret" {
		t.Fatalf("recovery url = %s", got)
	}
	if strings.Contains(got, "evil.example") || strings.Contains(got, "redirect=") {
		t.Fatalf("action url retained caller controlled query: %s", got)
	}

	got, err = emailActionURL("https://account.example.com/app", types.EmailActionPurposeEmailChange, "change.secret")
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	if got != "https://account.example.com/change-email#token=change.secret" {
		t.Fatalf("email change url = %s", got)
	}
}
