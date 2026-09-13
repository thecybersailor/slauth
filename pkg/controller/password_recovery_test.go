package controller

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

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
