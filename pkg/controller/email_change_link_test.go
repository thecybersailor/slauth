package controller

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

func TestEmailChangeLinkStartRequiresAAL2AndSendsToNewEmail(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	email := "old-email@example.com"
	hash, err := authService.GetPasswordService().HashPassword("correct horse battery staple 2026")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	userModel := models.User{InstanceId: authService.GetInstanceId(), Email: &email, EncryptedPassword: &hash, EmailConfirmedAt: &now, ConfirmedAt: &now, RawUserMetaData: &models.JSON{}, RawAppMetaData: &models.JSON{}}
	if err := db.Create(&userModel).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	user, err := authService.GetUserService().GetByID(t.Context(), userModel.ID, authService.GetInstanceId())
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	serviceUser, err := services.NewUserFromModelWithHashIDService(user, authService.GetPasswordService(), services.NewSessionService(db), db, authService.GetInstanceId(), services.NewHashIDService(authService.GetConfig()))
	if err != nil {
		t.Fatalf("wrap user: %v", err)
	}
	_, aal1Token, _, _, err := authService.CreateSession(t.Context(), serviceUser, types.AALLevel1, []string{"password"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create aal1 session: %v", err)
	}
	aal1 := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link", aal1Token, map[string]any{"email": "new-email@example.com"})
	if !strings.Contains(aal1.Body.String(), "auth.insufficient_aal") {
		t.Fatalf("aal1 response = %s", aal1.Body.String())
	}
	_, aal2Token, _, _, err := authService.CreateSession(t.Context(), serviceUser, types.AALLevel2, []string{"password", "email"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create aal2 session: %v", err)
	}
	resp := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link", aal2Token, map[string]any{"email": "new-email@example.com"})
	if resp.Code != http.StatusOK {
		t.Fatalf("email change start status=%d body=%s", resp.Code, resp.Body.String())
	}
	if emails.last == nil || emails.last.to != "new-email@example.com" || !strings.Contains(emails.last.body, "/change-email#token=") {
		t.Fatalf("unexpected email change mail: %+v", emails.last)
	}
	var saved models.User
	if err := db.First(&saved, userModel.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if saved.Email == nil || *saved.Email != email {
		t.Fatalf("email changed before confirmation: %+v", saved.Email)
	}
	var challenge models.EmailActionChallenge
	if err := db.Where("purpose = ? AND email = ?", string(types.EmailActionPurposeEmailChange), "new-email@example.com").First(&challenge).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if challenge.OriginalEmail != email || challenge.UserID == nil || *challenge.UserID != userModel.ID {
		t.Fatalf("challenge not bound to original user: %+v", challenge)
	}
}

func TestEmailChangeLinkCompleteUpdatesEmailAndRevokesSessions(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	oldEmail := "old-complete@example.com"
	newEmail := "new-complete@example.com"
	oldPassword := "correct horse battery staple 2026"
	hash, err := authService.GetPasswordService().HashPassword(oldPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	userModel := models.User{InstanceId: authService.GetInstanceId(), Email: &oldEmail, EncryptedPassword: &hash, EmailConfirmedAt: &now, ConfirmedAt: &now, RawUserMetaData: &models.JSON{}, RawAppMetaData: &models.JSON{}}
	if err := db.Create(&userModel).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	user, err := authService.GetUserService().GetByID(t.Context(), userModel.ID, authService.GetInstanceId())
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	serviceUser, err := services.NewUserFromModelWithHashIDService(user, authService.GetPasswordService(), services.NewSessionService(db), db, authService.GetInstanceId(), services.NewHashIDService(authService.GetConfig()))
	if err != nil {
		t.Fatalf("wrap user: %v", err)
	}
	_, accessToken, refreshToken, _, err := authService.CreateSession(t.Context(), serviceUser, types.AALLevel2, []string{"password", "email"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	start := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link", accessToken, map[string]any{"email": newEmail})
	if start.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", start.Code, start.Body.String())
	}
	token := extractEmailActionToken(t, emails.last.body)
	recovery := models.EmailActionChallenge{ID: "old-recovery-token", InstanceId: authService.GetInstanceId(), Purpose: string(types.EmailActionPurposeRecovery), UserID: &userModel.ID, Email: oldEmail, SecretDigest: "digest", ExpiresAt: now.Add(time.Hour)}
	reauth := models.EmailActionChallenge{ID: "old-reauth-token", InstanceId: authService.GetInstanceId(), Purpose: string(types.EmailActionPurposeReauthentication), UserID: &userModel.ID, Email: oldEmail, SecretDigest: "digest", ExpiresAt: now.Add(time.Hour)}
	if err := db.Create(&recovery).Error; err != nil {
		t.Fatalf("create recovery challenge: %v", err)
	}
	if err := db.Create(&reauth).Error; err != nil {
		t.Fatalf("create reauth challenge: %v", err)
	}

	complete := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link/complete", accessToken, map[string]any{"token": token})
	if complete.Code != http.StatusOK || !strings.Contains(complete.Body.String(), `"success":true`) {
		t.Fatalf("complete status=%d body=%s", complete.Code, complete.Body.String())
	}
	if strings.Contains(complete.Body.String(), "access_token") || strings.Contains(complete.Body.String(), "refresh_token") {
		t.Fatalf("email change complete should not create session: %s", complete.Body.String())
	}
	var saved models.User
	if err := db.First(&saved, userModel.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if saved.Email == nil || *saved.Email != newEmail {
		t.Fatalf("email = %+v, want %s", saved.Email, newEmail)
	}
	if saved.EmailConfirmedAt == nil || saved.ConfirmedAt == nil {
		t.Fatalf("email should remain confirmed: %+v", saved)
	}
	oldLogin := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{"email": oldEmail, "password": oldPassword})
	if !strings.Contains(oldLogin.Body.String(), "auth.invalid_credentials") {
		t.Fatalf("old email password login should fail: %s", oldLogin.Body.String())
	}
	newLogin := doJSONRequest(t, router, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]any{"email": newEmail, "password": oldPassword})
	if !strings.Contains(newLogin.Body.String(), "access_token") {
		t.Fatalf("new email password login should work: %s", newLogin.Body.String())
	}
	var activeSessions int64
	if err := db.Model(&models.Session{}).Where("user_id = ? AND (not_after IS NULL OR not_after > ?)", userModel.ID, time.Now()).Count(&activeSessions).Error; err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if activeSessions != 1 {
		t.Fatalf("expected only new login session active, got %d", activeSessions)
	}
	if _, err := authService.ValidateRefreshToken(t.Context(), refreshToken); err == nil {
		t.Fatal("old refresh token should be revoked")
	}
	for _, id := range []string{"old-recovery-token", "old-reauth-token"} {
		var challenge models.EmailActionChallenge
		if err := db.First(&challenge, "id = ?", id).Error; err != nil {
			t.Fatalf("load challenge %s: %v", id, err)
		}
		if challenge.ConsumedAt == nil {
			t.Fatalf("challenge %s was not invalidated", id)
		}
	}
	if emails.last == nil || emails.last.to != oldEmail || !strings.Contains(emails.last.subject, "Email changed") {
		t.Fatalf("old email notification not sent: %+v", emails.last)
	}
}

func TestEmailChangeLinkCompleteRejectsWrongSessionAndStaleOriginalEmail(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	oldEmail := "stale-old@example.com"
	newEmail := "stale-new@example.com"
	hash, err := authService.GetPasswordService().HashPassword("correct horse battery staple 2026")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	userModel := models.User{InstanceId: authService.GetInstanceId(), Email: &oldEmail, EncryptedPassword: &hash, EmailConfirmedAt: &now, ConfirmedAt: &now, RawUserMetaData: &models.JSON{}, RawAppMetaData: &models.JSON{}}
	if err := db.Create(&userModel).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	user, err := authService.GetUserService().GetByID(t.Context(), userModel.ID, authService.GetInstanceId())
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	serviceUser, err := services.NewUserFromModelWithHashIDService(user, authService.GetPasswordService(), services.NewSessionService(db), db, authService.GetInstanceId(), services.NewHashIDService(authService.GetConfig()))
	if err != nil {
		t.Fatalf("wrap user: %v", err)
	}
	_, firstToken, _, _, err := authService.CreateSession(t.Context(), serviceUser, types.AALLevel2, []string{"password", "email"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create first session: %v", err)
	}
	start := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link", firstToken, map[string]any{"email": newEmail})
	if start.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", start.Code, start.Body.String())
	}
	token := extractEmailActionToken(t, emails.last.body)
	_, secondToken, _, _, err := authService.CreateSession(t.Context(), serviceUser, types.AALLevel2, []string{"password", "email"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	wrongSession := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link/complete", secondToken, map[string]any{"token": token})
	if !strings.Contains(wrongSession.Body.String(), "auth.validation_failed") {
		t.Fatalf("wrong session response = %s", wrongSession.Body.String())
	}
	changedEmail := "already-changed@example.com"
	if err := db.Model(&models.User{}).Where("id = ?", userModel.ID).Update("email", changedEmail).Error; err != nil {
		t.Fatalf("change original email: %v", err)
	}
	stale := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/email/change/link/complete", firstToken, map[string]any{"token": token})
	if !strings.Contains(stale.Body.String(), "auth.validation_failed") {
		t.Fatalf("stale original email response = %s", stale.Body.String())
	}
	var saved models.User
	if err := db.First(&saved, userModel.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if saved.Email == nil || *saved.Email != changedEmail {
		t.Fatalf("stale token changed email to %+v", saved.Email)
	}
	var challenge models.EmailActionChallenge
	if err := db.Where("purpose = ? AND email = ?", string(types.EmailActionPurposeEmailChange), newEmail).First(&challenge).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if challenge.ConsumedAt != nil {
		t.Fatal("failed stale attempt consumed challenge")
	}
}

func extractEmailActionToken(t *testing.T, body string) string {
	t.Helper()
	prefix := "#token="
	idx := strings.Index(body, prefix)
	if idx < 0 {
		t.Fatalf("email body missing action token: %s", body)
	}
	token := body[idx+len(prefix):]
	if end := strings.IndexAny(token, " \n\t"); end >= 0 {
		token = token[:end]
	}
	if token == "" {
		t.Fatalf("empty action token in body: %s", body)
	}
	return token
}
