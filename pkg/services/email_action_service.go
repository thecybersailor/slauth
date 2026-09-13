package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EmailActionService struct {
	db          *gorm.DB
	appSecret   string
	now         func() time.Time
	maxAttempts int
}

func NewEmailActionService(db *gorm.DB, appSecret string) *EmailActionService {
	return &EmailActionService{
		db:          db,
		appSecret:   appSecret,
		now:         time.Now,
		maxAttempts: defaultEmailAuthPolicy().MaxAttempts,
	}
}

func (s *EmailActionService) WithClock(now func() time.Time) *EmailActionService {
	s.now = now
	return s
}

func (s *EmailActionService) WithMaxAttempts(maxAttempts int) *EmailActionService {
	if maxAttempts > 0 {
		s.maxAttempts = maxAttempts
	}
	return s
}

func (s *EmailActionService) Issue(ctx context.Context, req types.EmailActionIssueRequest) (*types.EmailActionIssueResult, error) {
	if !isValidEmailActionPurpose(req.Purpose) || req.InstanceID == "" || strings.TrimSpace(req.Email) == "" || req.TTL <= 0 {
		return nil, consts.VALIDATION_FAILED
	}

	id, err := GenerateSecureToken(16)
	if err != nil {
		return nil, err
	}
	secret, err := generateEmailActionSecret(req.SecretKind)
	if err != nil {
		return nil, err
	}

	now := s.now()
	expiresAt := now.Add(req.TTL)
	challenge := &models.EmailActionChallenge{
		ID:                  id,
		InstanceId:          req.InstanceID,
		Purpose:             string(req.Purpose),
		UserID:              req.UserID,
		SessionID:           req.SessionID,
		Email:               strings.ToLower(strings.TrimSpace(req.Email)),
		OriginalEmail:       strings.ToLower(strings.TrimSpace(req.OriginalEmail)),
		SecretDigest:        emailActionDigest(s.appSecret, req.InstanceID, string(req.Purpose), id, secret),
		PendingPasswordHash: req.PendingPasswordHash,
		CredentialDigest:    req.CredentialDigest,
		ExpiresAt:           expiresAt,
		LastSentAt:          now,
	}
	if err := s.db.WithContext(ctx).Create(challenge).Error; err != nil {
		return nil, err
	}

	return &types.EmailActionIssueResult{
		ID:        id,
		Secret:    secret,
		Token:     id + "." + secret,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *EmailActionService) Consume(ctx context.Context, instanceID string, purpose types.EmailActionPurpose, token string, operation func(tx *gorm.DB, challenge *models.EmailActionChallenge) error) error {
	id, secret, ok := splitEmailActionToken(token)
	if !ok || !isValidEmailActionPurpose(purpose) {
		return consts.VALIDATION_FAILED
	}

	var resultErr error
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var challenge models.EmailActionChallenge
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND instance_id = ? AND purpose = ?", id, instanceID, string(purpose)).
			First(&challenge).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				resultErr = consts.VALIDATION_FAILED
				return nil
			}
			return err
		}
		if challenge.ConsumedAt != nil {
			resultErr = consts.VALIDATION_FAILED
			return nil
		}
		if !challenge.ExpiresAt.After(s.now()) {
			resultErr = consts.OTP_EXPIRED
			return nil
		}
		if challenge.Attempts >= s.maxAttempts {
			resultErr = consts.VALIDATION_FAILED
			return nil
		}

		expected := emailActionDigest(s.appSecret, instanceID, string(purpose), id, secret)
		if !hmac.Equal([]byte(expected), []byte(challenge.SecretDigest)) {
			if err := tx.Model(&challenge).Update("attempts", challenge.Attempts+1).Error; err != nil {
				return err
			}
			resultErr = consts.BAD_CODE_VERIFIER
			return nil
		}

		if operation != nil {
			if err := operation(tx, &challenge); err != nil {
				return err
			}
		}
		consumedAt := s.now()
		result := tx.Model(&models.EmailActionChallenge{}).
			Where("id = ? AND consumed_at IS NULL", challenge.ID).
			Updates(map[string]any{"consumed_at": consumedAt, "updated_at": consumedAt})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			resultErr = consts.VALIDATION_FAILED
		}
		return nil
	})
	if err != nil {
		return err
	}
	return resultErr
}

func emailActionDigest(key, instance, purpose, id, secret string) string {
	mac := hmac.New(sha256.New, []byte(key))
	for _, value := range []string{instance, purpose, id, secret} {
		mac.Write([]byte(strconv.Itoa(len(value))))
		mac.Write([]byte(":"))
		mac.Write([]byte(value))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func splitEmailActionToken(token string) (string, string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func generateEmailActionSecret(kind types.EmailActionSecretKind) (string, error) {
	switch kind {
	case types.EmailActionSecretKindCode:
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%06d", n.Int64()), nil
	case types.EmailActionSecretKindLink:
		return GenerateSecureToken(32)
	default:
		return "", consts.VALIDATION_FAILED
	}
}

func isValidEmailActionPurpose(purpose types.EmailActionPurpose) bool {
	switch purpose {
	case types.EmailActionPurposeSignup,
		types.EmailActionPurposeReauthentication,
		types.EmailActionPurposeRecovery,
		types.EmailActionPurposeEmailChange:
		return true
	default:
		return false
	}
}
