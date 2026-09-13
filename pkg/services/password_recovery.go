package services

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/types"
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
	link, err := recoveryActionURL(s.authService.GetConfig().SiteURL, issued.Token)
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

func recoveryActionURL(siteURL, token string) (string, error) {
	u, err := url.Parse(siteURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", consts.VALIDATION_FAILED
	}
	u.Path = "/reset-password"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = url.Values{"token": []string{token}}.Encode()
	return strings.TrimRight(u.String(), "/"), nil
}
