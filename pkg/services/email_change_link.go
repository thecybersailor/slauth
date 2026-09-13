package services

import (
	"context"
	"net/url"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
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
