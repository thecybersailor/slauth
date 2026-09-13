package services

import (
	"strings"
	"testing"
	"time"

	authconfig "github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestEmailChangeLinkCompleteConflictDoesNotConsumeToken(t *testing.T) {
	db, authService := newEmailChangeServiceTestAuth(t)
	oldEmail := "service-old@example.com"
	newEmail := "service-new@example.com"
	hash, err := authService.GetPasswordService().HashPassword("correct horse battery staple 2026")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	userModel := models.User{InstanceId: authService.GetInstanceId(), Email: &oldEmail, EncryptedPassword: &hash, EmailConfirmedAt: &now, ConfirmedAt: &now, RawUserMetaData: &models.JSON{}, RawAppMetaData: &models.JSON{}}
	occupied := models.User{InstanceId: authService.GetInstanceId(), Email: &newEmail, RawUserMetaData: &models.JSON{}, RawAppMetaData: &models.JSON{}}
	if err := db.Create(&userModel).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.Create(&occupied).Error; err != nil {
		t.Fatalf("create occupied user: %v", err)
	}
	user, err := authService.GetUserService().GetByID(t.Context(), userModel.ID, authService.GetInstanceId())
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	serviceUser, err := NewUserFromModelWithHashIDService(user, authService.GetPasswordService(), NewSessionService(db), db, authService.GetInstanceId(), NewHashIDService(authService.GetConfig()))
	if err != nil {
		t.Fatalf("wrap user: %v", err)
	}
	aal2 := types.AALLevel2
	session := models.Session{UserID: userModel.ID, InstanceId: authService.GetInstanceId(), AAL: &aal2}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("create session: %v", err)
	}
	issued, err := NewEmailActionService(db, authService.GetConfig().AppSecret).Issue(t.Context(), types.EmailActionIssueRequest{
		InstanceID:    authService.GetInstanceId(),
		Purpose:       types.EmailActionPurposeEmailChange,
		SecretKind:    types.EmailActionSecretKindLink,
		UserID:        &userModel.ID,
		SessionID:     &session.ID,
		Email:         newEmail,
		OriginalEmail: oldEmail,
		TTL:           time.Minute,
	})
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	err = NewEmailChangeLinkService(authService).Complete(t.Context(), serviceUser, session.ID, types.AALLevel2, issued.Token)
	if err != consts.USER_ALREADY_EXISTS {
		t.Fatalf("complete err = %v, want conflict", err)
	}
	var challenge models.EmailActionChallenge
	if err := db.First(&challenge, "id = ?", issued.ID).Error; err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if challenge.ConsumedAt != nil {
		t.Fatal("conflict consumed challenge")
	}
	var saved models.User
	if err := db.First(&saved, userModel.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if saved.Email == nil || *saved.Email != oldEmail {
		t.Fatalf("conflict changed email to %+v", saved.Email)
	}
}

func newEmailChangeServiceTestAuth(t *testing.T) (*gorm.DB, *AuthServiceImpl) {
	t.Helper()
	dbName := "file:" + strings.NewReplacer("/", "_", " ", "_", "-", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate models: %v", err)
	}
	cfg := authconfig.NewDefaultAuthServiceConfig()
	cfg.AuthServiceBaseUrl = "https://account.example.com/auth/v1"
	cfg.SiteURL = "https://account.example.com"
	cfg.RatelimitConfig.EmailRateLimit.MaxRequests = 0
	cfg.RatelimitConfig.TokenVerificationRateLimit.MaxRequests = 0
	cfg.RatelimitConfig.SignUpSignInRateLimit.MaxRequests = 0
	if err := db.Create(&models.AuthInstance{InstanceId: "web_user", ConfigData: cfg}).Error; err != nil {
		t.Fatalf("create auth instance config: %v", err)
	}
	return db, NewAuthServiceImpl(db, NewStaticSecretsProvider(&types.InstanceSecrets{AppSecret: "email-change-service-secret"}), "web_user")
}
