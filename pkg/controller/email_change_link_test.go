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
