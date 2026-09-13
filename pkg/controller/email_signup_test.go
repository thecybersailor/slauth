package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

func TestEmailSignupStartCreatesOnlyChallenge(t *testing.T) {
	router, db, _, emails := newEmailMagicLinkTestRouter(t)
	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email", map[string]any{
		"email":    "Signup@Example.COM",
		"password": "correct horse battery staple 2026",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("signup start status = %d, body = %s", resp.Code, resp.Body.String())
	}
	var envelope struct {
		Data types.EmailSignupChallengeResponse `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data.ChallengeID == "" || envelope.Data.ExpiresIn <= 0 {
		t.Fatalf("invalid challenge response: %+v", envelope.Data)
	}
	if strings.Contains(resp.Body.String(), "correct horse") {
		t.Fatalf("response leaked password: %s", resp.Body.String())
	}
	if emails.last == nil || !regexp.MustCompile(`\b\d{6}\b`).MatchString(emails.last.body) {
		t.Fatalf("signup email missing code: %+v", emails.last)
	}
	assertAuthCounts(t, db, 0, 0, 0)
}

func TestEmailSignupExistingEmailDoesNotOverwriteUser(t *testing.T) {
	router, db, authService, _ := newEmailMagicLinkTestRouter(t)
	email := "existing@example.com"
	originalHash := "encoded:original-password"
	if err := db.Create(&models.User{
		InstanceId:        authService.GetInstanceId(),
		Email:             &email,
		EncryptedPassword: &originalHash,
	}).Error; err != nil {
		t.Fatalf("create existing user: %v", err)
	}
	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email", map[string]any{
		"email":    email,
		"password": "different correct horse battery 2026",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("signup start status = %d, body = %s", resp.Code, resp.Body.String())
	}
	var saved models.User
	if err := db.Where("email = ?", email).First(&saved).Error; err != nil {
		t.Fatalf("load existing user: %v", err)
	}
	if saved.EncryptedPassword == nil || *saved.EncryptedPassword != originalHash {
		t.Fatalf("existing password hash was overwritten: %#v", saved.EncryptedPassword)
	}
	var challenge models.EmailActionChallenge
	if err := db.Where("email = ? AND purpose = ?", email, string(types.EmailActionPurposeSignup)).First(&challenge).Error; err != nil {
		t.Fatalf("load signup challenge: %v", err)
	}
	if challenge.PendingPasswordHash != nil {
		t.Fatal("existing email challenge should not store a replacement password hash")
	}
}

func TestEmailSignupResendRotatesCode(t *testing.T) {
	router, db, _, emails := newEmailMagicLinkTestRouter(t)
	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email", map[string]any{
		"email":    "resend@example.com",
		"password": "correct horse battery staple 2026",
	})
	var envelope struct {
		Data types.EmailSignupChallengeResponse `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	oldCode := regexp.MustCompile(`\b\d{6}\b`).FindString(emails.last.body)
	if oldCode == "" {
		t.Fatalf("missing first code: %+v", emails.last)
	}
	if err := db.Model(&models.EmailActionChallenge{}).
		Where("id = ?", envelope.Data.ChallengeID).
		Update("last_sent_at", time.Now().Add(-2*time.Minute)).Error; err != nil {
		t.Fatalf("age challenge: %v", err)
	}
	resend := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email/resend", map[string]any{
		"challenge_id": envelope.Data.ChallengeID,
	})
	if resend.Code != http.StatusOK {
		t.Fatalf("resend status = %d, body = %s", resend.Code, resend.Body.String())
	}
	newCode := regexp.MustCompile(`\b\d{6}\b`).FindString(emails.last.body)
	if newCode == "" || newCode == oldCode {
		t.Fatalf("resend did not rotate code old=%q new=%q", oldCode, newCode)
	}
}

func TestEmailSignupResendBeforeCooldownIsRejected(t *testing.T) {
	router, _, _, _ := newEmailMagicLinkTestRouter(t)
	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email", map[string]any{
		"email":    "cooldown@example.com",
		"password": "correct horse battery staple 2026",
	})
	var envelope struct {
		Data types.EmailSignupChallengeResponse `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	resend := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email/resend", map[string]any{
		"challenge_id": envelope.Data.ChallengeID,
	})
	if !strings.Contains(resend.Body.String(), "auth.over_email_send_rate_limit") {
		t.Fatalf("resend body = %s, want cooldown error", resend.Body.String())
	}
}

func TestEmailSignupMailFailureDoesNotLeaveChallenge(t *testing.T) {
	router, db, authService := newPhoneOTPTestRouter(t)
	authService.SetEmailProvider(failingEmailProvider{})

	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/signup/email", map[string]any{
		"email":    "mailfail@example.com",
		"password": "correct horse battery staple 2026",
	})
	if !strings.Contains(resp.Body.String(), "email failed") {
		t.Fatalf("mail failure body = %s", resp.Body.String())
	}
	var count int64
	if err := db.Model(&models.EmailActionChallenge{}).Where("email = ?", "mailfail@example.com").Count(&count).Error; err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if count != 0 {
		t.Fatalf("mail failure left %d challenges", count)
	}
}

func assertAuthCounts(t *testing.T, db *gorm.DB, users, sessions, refreshTokens int64) {
	t.Helper()
	var gotUsers, gotSessions, gotRefresh int64
	if err := db.Model(&models.User{}).Count(&gotUsers).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := db.Model(&models.Session{}).Count(&gotSessions).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := db.Model(&models.RefreshToken{}).Count(&gotRefresh).Error; err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if gotUsers != users || gotSessions != sessions || gotRefresh != refreshTokens {
		t.Fatalf("counts users=%d sessions=%d refresh=%d, want %d/%d/%d", gotUsers, gotSessions, gotRefresh, users, sessions, refreshTokens)
	}
}

type failingEmailProvider struct{}

func (failingEmailProvider) SendEmail(context.Context, string, string, string) (*string, error) {
	return nil, errors.New("email failed")
}
