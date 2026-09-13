package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type PasswordRecoveryService struct {
	authService  AuthService
	emailActions *EmailActionService
	validator    *ValidatorService
}

func NewPasswordRecoveryService(authService AuthService) *PasswordRecoveryService {
	return &PasswordRecoveryService{
		authService:  authService,
		emailActions: NewEmailActionService(authService.GetDB(), authService.GetConfig().AppSecret),
		validator:    NewValidatorService(),
	}
}

func (s *PasswordRecoveryService) Request(ctx context.Context, email string) error {
	if err := s.validator.ValidateEmail(email); err != nil {
		return err
	}
	email = s.validator.SanitizeEmail(email)
	user, err := s.authService.GetUserService().GetByEmail(ctx, email)
	if err != nil {
		return nil
	}
	credential := "no-password"
	if user.User.EncryptedPassword != nil {
		credential = *user.User.EncryptedPassword
	}
	issued, err := s.emailActions.Issue(ctx, types.EmailActionIssueRequest{
		InstanceID:       s.authService.GetInstanceId(),
		Purpose:          types.EmailActionPurposeRecovery,
		SecretKind:       types.EmailActionSecretKindLink,
		UserID:           &user.User.ID,
		Email:            email,
		CredentialDigest: HashToken(credential),
		TTL:              30 * time.Minute,
	})
	if err != nil {
		return err
	}
	link, err := emailActionURL(s.authService.GetConfig().SiteURL, types.EmailActionPurposeRecovery, issued.Token)
	if err != nil {
		return err
	}
	provider := s.authService.GetEmailProvider()
	if provider == nil {
		return consts.UNEXPECTED_FAILURE
	}
	_, err = provider.SendEmail(ctx, email, "Reset your password", "Reset your password: "+link)
	return err
}

func (s *PasswordRecoveryService) Complete(ctx context.Context, token, password string) error {
	if err := s.authService.GetPasswordService().ValidateNewPassword(password); err != nil {
		return err
	}
	passwordHash, err := s.authService.GetPasswordService().HashPassword(password)
	if err != nil {
		return err
	}
	instanceID := s.authService.GetInstanceId()
	return s.emailActions.Consume(ctx, instanceID, types.EmailActionPurposeRecovery, token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
		if challenge.UserID == nil {
			return consts.VALIDATION_FAILED
		}
		var user models.User
		if err := tx.Where("id = ? AND instance_id = ?", *challenge.UserID, instanceID).First(&user).Error; err != nil {
			return err
		}
		if user.Email == nil || *user.Email != challenge.Email {
			return consts.VALIDATION_FAILED
		}
		currentCredential := "no-password"
		if user.EncryptedPassword != nil {
			currentCredential = *user.EncryptedPassword
		}
		if HashToken(currentCredential) != challenge.CredentialDigest {
			return consts.VALIDATION_FAILED
		}
		now := time.Now()
		if err := tx.Model(&user).Updates(map[string]any{
			"encrypted_password": passwordHash,
			"email_confirmed_at": now,
			"confirmed_at":       now,
			"updated_at":         now,
		}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.Session{}).
			Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)", user.ID, instanceID, now).
			Updates(map[string]any{"not_after": now, "updated_at": now}).Error; err != nil {
			return err
		}
		return tx.Model(&models.RefreshToken{}).
			Where("user_id = ? AND instance_id = ?", user.ID, instanceID).
			Updates(map[string]any{"revoked": true, "updated_at": now}).Error
	})
}
