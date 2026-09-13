package services

import (
	"context"
	"net/url"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EmailChangeLinkService struct {
	authService AuthService
	validator   *ValidatorService
}

func NewEmailChangeLinkService(authService AuthService) *EmailChangeLinkService {
	return &EmailChangeLinkService{authService: authService, validator: NewValidatorService()}
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
	issued, err := NewEmailActionService(s.authService.GetDB(), s.authService.GetConfig().AppSecret).Issue(ctx, types.EmailActionIssueRequest{
		InstanceID:    s.authService.GetInstanceId(),
		Purpose:       types.EmailActionPurposeEmailChange,
		SecretKind:    types.EmailActionSecretKindLink,
		UserID:        &user.User.ID,
		SessionID:     &sessionID,
		Email:         newEmail,
		OriginalEmail: user.GetEmail(),
		TTL:           30 * time.Minute,
	})
	if err != nil {
		return err
	}
	link, err := emailChangeActionURL(s.authService.GetConfig().SiteURL, issued.Token)
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
	emailActions := NewEmailActionService(s.authService.GetDB(), s.authService.GetConfig().AppSecret)
	err := emailActions.Consume(ctx, instanceID, types.EmailActionPurposeEmailChange, token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
		if challenge.UserID == nil || *challenge.UserID != user.User.ID || challenge.SessionID == nil || *challenge.SessionID != sessionID {
			return consts.VALIDATION_FAILED
		}
		var currentUser models.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND instance_id = ?", user.User.ID, instanceID).First(&currentUser).Error; err != nil {
			return err
		}
		if currentUser.Email == nil || *currentUser.Email != challenge.OriginalEmail || challenge.OriginalEmail == "" {
			return consts.VALIDATION_FAILED
		}
		var currentSession models.Session
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND user_id = ? AND instance_id = ?", sessionID, currentUser.ID, instanceID).
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
		var occupied int64
		if err := tx.Model(&models.User{}).
			Where("instance_id = ? AND email = ? AND id <> ?", instanceID, challenge.Email, currentUser.ID).
			Count(&occupied).Error; err != nil {
			return err
		}
		if occupied > 0 {
			return consts.USER_ALREADY_EXISTS
		}
		result := tx.Model(&models.User{}).
			Where("id = ? AND instance_id = ? AND email = ?", currentUser.ID, instanceID, challenge.OriginalEmail).
			Updates(map[string]any{
				"email":              challenge.Email,
				"email_confirmed_at": now,
				"confirmed_at":       now,
				"updated_at":         now,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return consts.VALIDATION_FAILED
		}
		if err := tx.Model(&models.Session{}).
			Where("user_id = ? AND instance_id = ? AND (not_after IS NULL OR not_after > ?)", currentUser.ID, instanceID, now).
			Updates(map[string]any{"not_after": now, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.RefreshToken{}).
			Where("user_id = ? AND instance_id = ?", currentUser.ID, instanceID).
			Updates(map[string]any{"revoked": true, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.EmailActionChallenge{}).
			Where("id <> ? AND instance_id = ? AND consumed_at IS NULL AND (user_id = ? OR email = ? OR original_email = ?)", challenge.ID, instanceID, currentUser.ID, challenge.OriginalEmail, challenge.OriginalEmail).
			Updates(map[string]any{"consumed_at": now, "updated_at": now}).Error; err != nil {
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

func emailChangeActionURL(siteURL, token string) (string, error) {
	u, err := url.Parse(siteURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", consts.VALIDATION_FAILED
	}
	u.Path = "/change-email"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = url.Values{"token": []string{token}}.Encode()
	return u.String(), nil
}
