package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

func TestEmailReauthenticationUpgradesCurrentSession(t *testing.T) {
	router, db, authService, emails := newEmailMagicLinkTestRouter(t)
	email := "reauth@example.com"
	hash, err := authService.GetPasswordService().HashPassword("correct horse battery staple 2026")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	userModel := models.User{
		InstanceId:        authService.GetInstanceId(),
		Email:             &email,
		EncryptedPassword: &hash,
		EmailConfirmedAt:  &now,
		ConfirmedAt:       &now,
		RawUserMetaData:   &models.JSON{},
		RawAppMetaData:    &models.JSON{},
	}
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
	_, accessToken, _, _, err := authService.CreateSession(t.Context(), serviceUser, types.AALLevel1, []string{"password"}, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	start := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/reauthenticate", accessToken, map[string]any{"channel": "email"})
	var startEnvelope struct {
		Data ReauthenticateData `json:"data"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &startEnvelope); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	code := regexp.MustCompile(`\b\d{6}\b`).FindString(emails.last.body)
	if code == "" || startEnvelope.Data.SessionCode == "" {
		t.Fatalf("missing reauth code/session_code body=%s email=%+v", start.Body.String(), emails.last)
	}
	verify := doAuthorizedJSONRequest(t, router, http.MethodPost, "/auth/v1/reauthenticate/verify", accessToken, map[string]any{
		"channel":      "email",
		"session_code": startEnvelope.Data.SessionCode,
		"token":        code,
	})
	if !strings.Contains(verify.Body.String(), `"success":true`) {
		t.Fatalf("verify body = %s", verify.Body.String())
	}
	claims, err := authService.ValidateJWT(accessToken)
	if err != nil {
		t.Fatalf("validate jwt: %v", err)
	}
	if claims["aal"] != types.AALLevel2 {
		t.Fatalf("aal = %#v, want aal2", claims["aal"])
	}
}

func doAuthorizedJSONRequest(t *testing.T, router http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
