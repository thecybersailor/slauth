package models

import (
	"log/slog"
	"time"

	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type Session struct {
	ID        uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID    uint      `json:"user_id" gorm:"not null;index"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// FactorID    *uuid.UUID      `json:"factor_id" gorm:"type:uuid"`
	AAL          *types.AALLevel `json:"aal" gorm:"type:varchar(10)"`
	AALExpiresAt *time.Time      `json:"aal_expires_at" gorm:"type:timestamp"`
	NotAfter     *time.Time      `json:"not_after"`
	RefreshedAt  *time.Time      `json:"refreshed_at" gorm:"type:timestamp"`
	UserAgent    *string         `json:"user_agent" gorm:"type:varchar(255)"`
	IP           *string         `json:"ip" gorm:"type:varchar(255)"`
	Tag          *string         `json:"tag" gorm:"type:varchar(255)"`
	DomainCode   string          `json:"domain_code" gorm:"type:varchar(255)"`

	// Relationships
	User          *User          `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
	RefreshTokens []RefreshToken `json:"refresh_tokens,omitempty" gorm:"foreignKey:SessionID"`
	MFAAMRClaims  []MFAAMRClaim  `json:"mfa_amr_claims,omitempty" gorm:"foreignKey:SessionID"`
}

func (s *Session) AfterFind(tx *gorm.DB) error {

	if s.AAL != nil && *s.AAL == types.AALLevel2 {
		if s.AALExpiresAt != nil {
			now := time.Now()
			expiresAtUTC := s.AALExpiresAt.UTC()
			nowUTC := now.UTC()
			isExpired := nowUTC.After(expiresAtUTC)

			slog.Info("Session AfterFind: AAL expiry check",
				"sessionID", s.ID,
				"currentAAL", *s.AAL,
				"expiresAt", *s.AALExpiresAt,
				"expiresAtUTC", expiresAtUTC,
				"nowUTC", nowUTC,
				"isExpired", isExpired,
				"timeDiff", nowUTC.Sub(expiresAtUTC).Seconds(),
			)

			if isExpired {

				slog.Info("Session AfterFind: AAL expired, auto-downgrading", "sessionID", s.ID)

				err := tx.Model(s).Where("id = ? AND domain_code = ?", s.ID, s.DomainCode).
					Update("aal", types.AALLevel1).Error
				if err != nil {
					slog.Warn("Session AfterFind: Failed to downgrade expired AAL", "sessionID", s.ID, "error", err)
					return err
				}

				aal1 := types.AALLevel1
				s.AAL = &aal1

				slog.Info("Session AfterFind: AAL auto-downgraded from AAL2 to AAL1", "sessionID", s.ID)
			} else {
				slog.Info("Session AfterFind: AAL has not expired yet", "sessionID", s.ID, "remainingSeconds", expiresAtUTC.Sub(nowUTC).Seconds())
			}
		} else {
			slog.Info("Session AfterFind: AAL2 session has no expiry time set", "sessionID", s.ID)
		}
	} else {
		if s.AAL == nil {
			slog.Info("Session AfterFind: Session has no AAL set", "sessionID", s.ID)
		} else {
			slog.Info("Session AfterFind: Session is not AAL2", "sessionID", s.ID, "currentAAL", *s.AAL)
		}
	}

	return nil
}
