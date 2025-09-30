package services

import (
	"fmt"

	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

// NewUserIdentity creates a new UserIdentity object
func NewUserIdentity(identity *models.Identity) (*UserIdentity, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity cannot be nil")
	}

	hashid, err := GetUserIDFromHashID(fmt.Sprintf("%d", identity.ID))
	if err != nil {
		return nil, fmt.Errorf("failed to generate hashid for identity %d: %w", identity.ID, err)
	}

	return &UserIdentity{
		Identity: identity,
		HashID:   fmt.Sprintf("%d", hashid),
	}, nil
}

// AdminIdentityService provides admin operations for identity management
type AdminIdentityService struct {
	db *gorm.DB
}

// NewAdminIdentityService creates a new admin identity service
func NewAdminIdentityService(db *gorm.DB) *AdminIdentityService {
	return &AdminIdentityService{db: db}
}

type UserIdentity struct {
	*models.Identity
	HashID string `json:"hashid"`
}

func (ui *UserIdentity) GetModel() *models.Identity {
	return ui.Identity
}
