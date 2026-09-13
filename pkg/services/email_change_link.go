package services

import (
	"context"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EmailChangeLinkService struct {
	authService AuthService
	validator   *ValidatorService
	policy      config.EmailAuthPolicy
}

func NewEmailChangeLinkService(authService AuthService) *EmailChangeLinkService {
	return &EmailChangeLinkService{authService: authService, validator: NewValidatorService(), policy: EmailAuthPolicyFromConfig(authService.GetConfig())}
}

func (s *EmailChangeLinkService) Start(ctx context.Context, user *User, sessionID uint, currentAAL types.AALLevel, newEmail string) error {
	if currentAAL != types.AALLevel2 {
		return consts.INSUFFICIENT_AAL
	}
	if err := s.validator.ValidateEmail(newEmail); err != nil {
		return err
	}
	newEmail = s.validator.SanitizeEmail(newEmail)
	if user.GetEmail() == newEmail {
		return consts.VALIDATION_FAILED
	}
	if _, err := s.authService.GetUserService().GetByEmail(ctx, newEmail); err == nil {
		return consts.USER_ALREADY_EXISTS
	} else if err != gorm.ErrRecordNotFound {
		return err
	}
	issued, err := NewEmailActionService(s.authService.GetDB(), s.authService.GetConfig().AppSecret).WithMaxAttempts(s.policy.MaxAttempts).Issue(ctx, types.EmailActionIssueRequest{
		InstanceID:    s.authService.GetInstanceId(),
		Purpose:       types.EmailActionPurposeEmailChange,
		SecretKind:    types.EmailActionSecretKindLink,
		UserID:        &user.User.ID,
		SessionID:     &sessionID,
		Email:         newEmail,
		OriginalEmail: user.GetEmail(),
		TTL:           s.policy.LinkTTL,
	})
	if err != nil {
		return err
	}
	link, err := emailActionURL(s.authService.GetConfig().SiteURL, types.EmailActionPurposeEmailChange, issued.Token)
	if err != nil {
		return err
	}
	provider := s.authService.GetEmailProvider()
	if provider == nil {
		return consts.UNEXPECTED_FAILURE
	}
	_, err = provider.SendEmail(ctx, newEmail, "Confirm your new email", "Confirm your new email: "+link)
	return err
}

func (s *EmailChangeLinkService) Complete(ctx context.Context, user *User, sessionID uint, currentAAL types.AALLevel, token string) error {
	if currentAAL != types.AALLevel2 {
		return consts.INSUFFICIENT_AAL
	}
	instanceID := s.authService.GetInstanceId()
	var originalEmail string
	var changedEmail string
	emailActions := NewEmailActionService(s.authService.GetDB(), s.authService.GetConfig().AppSecret).WithMaxAttempts(s.policy.MaxAttempts)
	err := emailActions.Consume(ctx, instanceID, types.EmailActionPurposeEmailChange, token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
		if challenge.UserID == nil || *challenge.UserID != user.User.ID || challenge.SessionID == nil || *challenge.SessionID != sessionID {
			return consts.VALIDATION_FAILED
		}
		var currentSession models.Session
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND user_id = ? AND instance_id = ?", sessionID, user.User.ID, instanceID).
			First(&currentSession).Error; err != nil {
			return err
		}
		now := time.Now()
		if currentSession.NotAfter != nil && !currentSession.NotAfter.After(now) {
			return consts.VALIDATION_FAILED
		}
		if currentSession.AAL == nil || *currentSession.AAL != types.AALLevel2 || (currentSession.AALExpiresAt != nil && !currentSession.AALExpiresAt.After(now)) {
			return consts.INSUFFICIENT_AAL
		}
		if err := CompleteVerifiedEmailChangeTx(tx, instanceID, user.User.ID, challenge.OriginalEmail, challenge.Email, EmailChangeCompletionOptions{
			Now:                now,
			ExcludeChallengeID: challenge.ID,
		}); err != nil {
			return err
		}
		originalEmail = challenge.OriginalEmail
		changedEmail = challenge.Email
		return nil
	})
	if err != nil {
		return err
	}
	if originalEmail != "" {
		if provider := s.authService.GetEmailProvider(); provider != nil {
			_, _ = provider.SendEmail(ctx, originalEmail, "Email changed", "Your account email was changed to "+changedEmail+". If you did not make this change, contact support.")
		}
	}
	return nil
}
