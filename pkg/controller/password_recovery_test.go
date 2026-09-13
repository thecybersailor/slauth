package controller

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
)

func TestPasswordRecoveryRequestIssuesScopedLink(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	email := "recover@example.com"
	hash, err := authService.GetPasswordService().HashPassword("correct horse battery staple 2026")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := db.Create(&models.User{InstanceId: authService.GetInstanceId(), Email: &email, EncryptedPassword: &hash}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	resp := doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover", map[string]any{"email": email})
	if resp.Code != http.StatusOK {
		t.Fatalf("recover status = %d body = %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "token") || strings.Contains(resp.Body.String(), "dummy_reset_token") {
		t.Fatalf("recover response leaked token: %s", resp.Body.String())
	}
	if emails.last == nil || !strings.Contains(emails.last.body, "/reset-password#token=") {
		t.Fatalf("recovery email missing action link: %+v", emails.last)
	}
	token := regexp.MustCompile(`#token=([^\\s]+)`).FindStringSubmatch(emails.last.body)
	if len(token) != 2 {
		t.Fatalf("recovery email missing token: %s", emails.last.body)
	}
	var challenge models.EmailActionChallenge
	if err := db.Where("email = ? AND purpose = ?", email, string(types.EmailActionPurposeRecovery)).First(&challenge).Error; err != nil {
		t.Fatalf("load recovery challenge: %v", err)
	}
	if strings.Contains(challenge.SecretDigest, token[1]) {
		t.Fatal("database stored raw recovery token")
	}
}

func TestPasswordRecoveryUnknownEmailMatchesPublicResponse(t *testing.T) {
	router, db, _, _ := newEmailMagicLinkTestRouter(t)
	existing := doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover", map[string]any{"email": "missing@example.com"})
	unknown := doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover", map[string]any{"email": "other@example.com"})
	if existing.Body.String() != unknown.Body.String() {
		t.Fatalf("unknown email response differed: %s vs %s", existing.Body.String(), unknown.Body.String())
	}
	var count int64
	if err := db.Model(&models.EmailActionChallenge{}).Where("purpose = ?", string(types.EmailActionPurposeRecovery)).Count(&count).Error; err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if count != 0 {
		t.Fatalf("unknown recover created %d challenges", count)
	}
}

func TestPasswordRecoveryRedirectCannotOverrideActionURL(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	email := "redirect-recover@example.com"
	hash, err := authService.GetPasswordService().HashPassword("correct horse battery staple 2026")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := db.Create(&models.User{InstanceId: authService.GetInstanceId(), Email: &email, EncryptedPassword: &hash}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover", map[string]any{
		"email": email,
		"options": map[string]any{
			"redirect_to": "https://evil.example.com/reset",
		},
	})
	if emails.last == nil {
		t.Fatal("expected recovery email")
	}
	if strings.Contains(emails.last.body, "evil.example.com") || !strings.Contains(emails.last.body, "https://account.example.com/reset-password#token=") {
		t.Fatalf("unexpected recovery URL: %s", emails.last.body)
	}
}

func TestPasswordRecoveryLegacyDummyTokenRejected(t *testing.T) {
	if _, _, ok := splitRecoverCompleteTokenForTest("dummy_reset_token"); ok {
		t.Fatal("dummy reset token should not parse as email action token")
	}
}

func TestPasswordRecoveryCompleteUpdatesPasswordAndRevokesSessions(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	email := "complete-recover@example.com"
	oldPassword := "correct horse battery staple 2026"
	hash, err := authService.GetPasswordService().HashPassword(oldPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	user := models.User{
		InstanceId:        authService.GetInstanceId(),
		Email:             &email,
		EncryptedPassword: &hash,
		EmailConfirmedAt:  &now,
		ConfirmedAt:       &now,
		RawUserMetaData:   &models.JSON{},
		RawAppMetaData:    &models.JSON{},
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	aal := types.AALLevel1
	session := models.Session{UserID: user.ID, InstanceId: authService.GetInstanceId(), AAL: &aal}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := db.Create(&models.RefreshToken{Token: "old-refresh-token", UserID: user.ID, SessionID: session.ID, InstanceId: authService.GetInstanceId()}).Error; err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover", map[string]any{"email": email})
	tokenMatch := regexp.MustCompile(`#token=([^\\s]+)`).FindStringSubmatch(emails.last.body)
	if len(tokenMatch) != 2 {
		t.Fatalf("missing recovery token: %s", emails.last.body)
	}
	token := tokenMatch[1]

	weak := doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover/complete", map[string]any{
		"token":    token,
		"password": "password",
	})
	if !strings.Contains(weak.Body.String(), "auth.weak_password") {
		t.Fatalf("weak complete body = %s", weak.Body.String())
	}

	complete := doJSONRequest(t, router, http.MethodPost, "/auth/v1/recover/complete", map[string]any{
		"token":    token,
		"password": "new correct horse battery staple 2026",
	})
	if complete.Code != http.StatusOK || !strings.Contains(complete.Body.String(), `"success":true`) {
		t.Fatalf("complete status=%d body=%s", complete.Code, complete.Body.String())
	}
	if strings.Contains(complete.Body.String(), "access_token") || strings.Contains(complete.Body.String(), "refresh_token") {
		t.Fatalf("complete should not create session: %s", complete.Body.String())
	}
	oldLogin := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{"email": email, "password": oldPassword})
	if !strings.Contains(oldLogin.Body.String(), "auth.invalid_credentials") {
		t.Fatalf("old password should fail: %s", oldLogin.Body.String())
	}
	newLogin := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{"email": email, "password": "new correct horse battery staple 2026"})
	if !strings.Contains(newLogin.Body.String(), "access_token") {
		t.Fatalf("new password should login: %s", newLogin.Body.String())
	}
	var activeSessions int64
	if err := db.Model(&models.Session{}).Where("user_id = ? AND (not_after IS NULL OR not_after > ?)", user.ID, time.Now()).Count(&activeSessions).Error; err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if activeSessions != 1 {
		t.Fatalf("expected only new login session active, got %d", activeSessions)
	}
	var revoked int64
	if err := db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked = ?", user.ID, true).Count(&revoked).Error; err != nil {
		t.Fatalf("count revoked refresh tokens: %v", err)
	}
	if revoked == 0 {
		t.Fatal("old refresh tokens were not revoked")
	}
}

func splitRecoverCompleteTokenForTest(token string) (string, string, bool) {
	parts := strings.Split(token, ".")
	return "", "", len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func decodeRecoveryResponse(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}
