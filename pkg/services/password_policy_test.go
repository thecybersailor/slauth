package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPasswordPolicyValidatesNewPasswords(t *testing.T) {
	service := NewPasswordServiceWithEncoderAndPolicy(&spyPasswordEncoder{}, config.PasswordStrengthConfig{
		MinScore:  0,
		MinLength: 15,
		MaxLength: 128,
		MaxBytes:  512,
	})

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{name: "empty", password: "", wantErr: consts.VALIDATION_FAILED},
		{name: "too short", password: "short password", wantErr: consts.WEAK_PASSWORD},
		{name: "too many characters", password: strings.Repeat("a", 129), wantErr: consts.VALIDATION_FAILED},
		{name: "too many bytes", password: strings.Repeat("界", 171), wantErr: consts.VALIDATION_FAILED},
		{name: "unicode and spaces allowed", password: "correct horse battery staple 東京 2026", wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateNewPassword(tt.password)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateNewPassword() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestUserUpdatePasswordUsesConfiguredPolicy(t *testing.T) {
	db := newPasswordPolicyTestDB(t)
	passwordService := NewPasswordServiceWithEncoderAndPolicy(&spyPasswordEncoder{}, config.PasswordStrengthConfig{
		MinScore:  0,
		MinLength: 15,
		MaxLength: 128,
		MaxBytes:  512,
	})
	userService := NewUserServiceWithInstance(db, "policy-instance").SetPasswordService(passwordService)
	email := "policy@example.com"
	user, err := userService.CreateUserWithSource(context.Background(), &UserCreateOptions{
		Email:    &email,
		Password: ptrString("valid password with spaces"),
	}, UserCreatedSourceSignup, nil, nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := user.UpdatePassword(context.Background(), "short password"); !errors.Is(err, consts.WEAK_PASSWORD) {
		t.Fatalf("UpdatePassword weak error = %v, want %v", err, consts.WEAK_PASSWORD)
	}

	var saved models.User
	if err := db.Where("id = ?", user.ID).First(&saved).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if saved.EncryptedPassword == nil || *saved.EncryptedPassword != "encoded:valid password with spaces" {
		t.Fatalf("weak password should not be saved, got %#v", saved.EncryptedPassword)
	}
}

func TestPasswordLoginFailuresUseDummyVerification(t *testing.T) {
	db := newPasswordPolicyTestDB(t)
	encoder := &spyPasswordEncoder{}
	passwordService := NewPasswordServiceWithEncoderAndPolicy(encoder, config.PasswordStrengthConfig{
		MinScore:  0,
		MinLength: 15,
		MaxLength: 128,
		MaxBytes:  512,
	})
	service := NewAuthServiceImplWithPasswordService(db, newPasswordPolicySecretsProvider(), "policy-instance", passwordService)

	noPasswordEmail := "nopassword@example.com"
	if _, err := service.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
		Email: &noPasswordEmail,
	}, UserCreatedSourceAdmin, nil, nil); err != nil {
		t.Fatalf("create no-password user: %v", err)
	}

	encoder.reset()
	if _, err := service.AuthenticateUser(context.Background(), "missing@example.com", "wrong password"); !errors.Is(err, consts.INVALID_CREDENTIALS) {
		t.Fatalf("missing user error = %v, want %v", err, consts.INVALID_CREDENTIALS)
	}
	if encoder.verifyCalls != 1 {
		t.Fatalf("missing user verify calls = %d, want 1", encoder.verifyCalls)
	}

	encoder.reset()
	if _, err := service.AuthenticateUser(context.Background(), noPasswordEmail, "wrong password"); !errors.Is(err, consts.INVALID_CREDENTIALS) {
		t.Fatalf("no-password user error = %v, want %v", err, consts.INVALID_CREDENTIALS)
	}
	if encoder.verifyCalls != 1 {
		t.Fatalf("no-password user verify calls = %d, want 1", encoder.verifyCalls)
	}
}

func TestPasswordLoginDoesNotApplyNewPasswordPolicyToStoredPasswords(t *testing.T) {
	db := newPasswordPolicyTestDB(t)
	encoder := &spyPasswordEncoder{}
	passwordService := NewPasswordServiceWithEncoderAndPolicy(encoder, config.PasswordStrengthConfig{
		MinScore:  0,
		MinLength: 15,
		MaxLength: 128,
		MaxBytes:  512,
	})
	service := NewAuthServiceImplWithPasswordService(db, newPasswordPolicySecretsProvider(), "policy-instance", passwordService)
	oldEmail := "oldshort@example.com"
	oldHash := "encoded:short"
	now := time.Now()
	if err := db.Create(&models.User{
		InstanceId:        "policy-instance",
		Email:             &oldEmail,
		EncryptedPassword: &oldHash,
		EmailConfirmedAt:  &now,
	}).Error; err != nil {
		t.Fatalf("create legacy user: %v", err)
	}

	if _, err := service.AuthenticateUser(context.Background(), oldEmail, "short"); err != nil {
		t.Fatalf("legacy short password should still authenticate: %v", err)
	}
}

type spyPasswordEncoder struct {
	verifyCalls int
}

func (e *spyPasswordEncoder) HashPassword(password string) (string, error) {
	return "encoded:" + password, nil
}

func (e *spyPasswordEncoder) VerifyPassword(password, encodedHash string) (bool, error) {
	e.verifyCalls++
	return encodedHash == "encoded:"+password, nil
}

func (e *spyPasswordEncoder) reset() {
	e.verifyCalls = 0
}

func newPasswordPolicyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/slauth-password-policy.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

func newPasswordPolicySecretsProvider() *StaticSecretsProvider {
	return NewStaticSecretsProvider(&types.InstanceSecrets{
		PrimaryKeyId: "password-policy-test-key",
		AppSecret:    "password-policy-test-secret",
		Keys:         map[string]*types.SigningKey{},
	})
}

func ptrString(value string) *string {
	return &value
}
