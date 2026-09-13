package services

import (
	"context"
	"fmt"
	"time"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type EmailSignupService struct {
	db              *gorm.DB
	instanceID      string
	passwordService *PasswordService
	emailActions    *EmailActionService
	emailProvider   types.EmailProvider
	validator       *ValidatorService
	policy          config.EmailAuthPolicy
	now             func() time.Time
}

func NewEmailSignupService(db *gorm.DB, instanceID string, passwordService *PasswordService, emailActions *EmailActionService, emailProvider types.EmailProvider) *EmailSignupService {
	return &EmailSignupService{
		db:              db,
		instanceID:      instanceID,
		passwordService: passwordService,
		emailActions:    emailActions,
		emailProvider:   emailProvider,
		validator:       NewValidatorService(),
		policy:          defaultEmailAuthPolicy(),
		now:             time.Now,
	}
}

func (s *EmailSignupService) WithEmailAuthPolicy(policy config.EmailAuthPolicy) *EmailSignupService {
	if policy.CodeTTL > 0 {
		s.policy.CodeTTL = policy.CodeTTL
	}
	if policy.LinkTTL > 0 {
		s.policy.LinkTTL = policy.LinkTTL
	}
	if policy.MaxAttempts > 0 {
		s.policy.MaxAttempts = policy.MaxAttempts
		s.emailActions.WithMaxAttempts(policy.MaxAttempts)
	}
	if policy.ResendInterval > 0 {
		s.policy.ResendInterval = policy.ResendInterval
	}
	return s
}

func (s *EmailSignupService) Start(ctx context.Context, email, password string) (*types.EmailSignupChallengeResponse, error) {
	if err := s.validator.ValidateEmail(email); err != nil {
		return nil, err
	}
	email = s.validator.SanitizeEmail(email)
	if err := s.passwordService.ValidateNewPassword(password); err != nil {
		return nil, err
	}
	passwordHash, err := s.passwordService.HashPassword(password)
	if err != nil {
		return nil, err
	}

	var existing models.User
	pendingHash := &passwordHash
	err = s.db.WithContext(ctx).Where("instance_id = ? AND email = ?", s.instanceID, email).First(&existing).Error
	if err == nil {
		pendingHash = nil
	} else if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	issued, err := s.emailActions.Issue(ctx, types.EmailActionIssueRequest{
		InstanceID:          s.instanceID,
		Purpose:             types.EmailActionPurposeSignup,
		SecretKind:          types.EmailActionSecretKindCode,
		Email:               email,
		PendingPasswordHash: pendingHash,
		TTL:                 s.policy.CodeTTL,
	})
	if err != nil {
		return nil, err
	}
	if err := s.sendSignupCode(ctx, email, issued.Secret); err != nil {
		_ = s.db.WithContext(ctx).Delete(&models.EmailActionChallenge{}, "id = ? AND instance_id = ?", issued.ID, s.instanceID).Error
		return nil, err
	}
	return signupChallengeResponse(issued, s.now()), nil
}

func (s *EmailSignupService) Resend(ctx context.Context, challengeID string) (*types.EmailSignupChallengeResponse, error) {
	var challenge models.EmailActionChallenge
	err := s.db.WithContext(ctx).
		Where("id = ? AND instance_id = ? AND purpose = ? AND consumed_at IS NULL", challengeID, s.instanceID, string(types.EmailActionPurposeSignup)).
		First(&challenge).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, consts.VALIDATION_FAILED
		}
		return nil, err
	}
	now := s.now()
	if now.Sub(challenge.LastSentAt) < s.policy.ResendInterval {
		return nil, consts.OVER_EMAIL_SEND_RATE_LIMIT
	}
	secret, err := generateEmailActionSecret(types.EmailActionSecretKindCode)
	if err != nil {
		return nil, err
	}
	updates := map[string]any{
		"secret_digest": emailActionDigest(s.emailActions.appSecret, s.instanceID, string(types.EmailActionPurposeSignup), challenge.ID, secret),
		"last_sent_at":  now,
		"updated_at":    now,
	}
	if err := s.db.WithContext(ctx).Model(&challenge).Updates(updates).Error; err != nil {
		return nil, err
	}
	if err := s.sendSignupCode(ctx, challenge.Email, secret); err != nil {
		return nil, err
	}
	result := &types.EmailActionIssueResult{ID: challenge.ID, Secret: secret, Token: challenge.ID + "." + secret, ExpiresAt: challenge.ExpiresAt}
	return signupChallengeResponse(result, now), nil
}

func (s *EmailSignupService) Verify(ctx context.Context, challengeID, code string) error {
	token := challengeID + "." + code
	return s.emailActions.Consume(ctx, s.instanceID, types.EmailActionPurposeSignup, token, func(tx *gorm.DB, challenge *models.EmailActionChallenge) error {
		if challenge.PendingPasswordHash == nil || *challenge.PendingPasswordHash == "" {
			return consts.VALIDATION_FAILED
		}
		var existing models.User
		err := tx.Where("instance_id = ? AND email = ?", s.instanceID, challenge.Email).First(&existing).Error
		if err == nil {
			return consts.USER_ALREADY_EXISTS
		}
		if err != gorm.ErrRecordNotFound {
			return err
		}
		now := s.now()
		user := &models.User{
			InstanceId:        s.instanceID,
			Email:             &challenge.Email,
			EncryptedPassword: challenge.PendingPasswordHash,
			EmailConfirmedAt:  &now,
			ConfirmedAt:       &now,
			RawUserMetaData:   &models.JSON{},
			RawAppMetaData:    &models.JSON{},
			CreatedAt:         now,
			UpdatedAt:         now,
			IsAnonymous:       false,
			IsSSOUser:         false,
		}
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		return tx.Model(challenge).Update("pending_password_hash", nil).Error
	})
}

func (s *EmailSignupService) sendSignupCode(ctx context.Context, email, code string) error {
	if s.emailProvider == nil {
		return consts.UNEXPECTED_FAILURE
	}
	_, err := s.emailProvider.SendEmail(ctx, email, "Email verification code", fmt.Sprintf("Your verification code is %s.", code))
	return err
}

func signupChallengeResponse(issued *types.EmailActionIssueResult, now time.Time) *types.EmailSignupChallengeResponse {
	expiresIn := int64(issued.ExpiresAt.Sub(now).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	return &types.EmailSignupChallengeResponse{
		Message:     "Verification code sent.",
		ChallengeID: issued.ID,
		ExpiresIn:   expiresIn,
	}
}
