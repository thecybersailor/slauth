package services

import (
	"log/slog"

	"github.com/speps/go-hashids/v2"
	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"gorm.io/gorm"
)

const (
	defaultHashIDSalt = "@cybersailor/slauth-ts-salt-2024"
	hashIDMinLength   = 18
)

type HashIDService struct {
	appSecret string
}

func NewHashIDService(config *config.AuthServiceConfig) *HashIDService {
	return &HashIDService{
		appSecret: config.AppSecret,
	}
}

var globalHashIDService *HashIDService

func SetGlobalHashIDService(service *HashIDService) {
	globalHashIDService = service
}

func getGlobalHashIDService() *HashIDService {
	if globalHashIDService == nil {

		return &HashIDService{appSecret: ""}
	}
	return globalHashIDService
}

func (h *HashIDService) GenerateHashID(id uint) (string, error) {
	salt := h.appSecret
	if salt == "" {
		salt = defaultHashIDSalt
	}

	hd := hashids.NewData()
	hd.Salt = salt
	hd.MinLength = hashIDMinLength

	hasher, err := hashids.NewWithData(hd)
	if err != nil {
		return "", consts.UNEXPECTED_FAILURE
	}

	hashid, err := hasher.Encode([]int{int(id)})
	if err != nil {
		return "", consts.UNEXPECTED_FAILURE
	}

	return hashid, nil
}

func (h *HashIDService) ParseHashID(hashid string) (uint, error) {
	salt := h.appSecret
	if salt == "" {
		salt = defaultHashIDSalt
	}

	hd := hashids.NewData()
	hd.Salt = salt
	hd.MinLength = hashIDMinLength

	hasher, err := hashids.NewWithData(hd)
	if err != nil {
		return 0, consts.UNEXPECTED_FAILURE
	}

	ids, err := hasher.DecodeWithError(hashid)
	if err != nil {
		return 0, consts.VALIDATION_FAILED
	}

	if len(ids) == 0 {
		return 0, consts.VALIDATION_FAILED
	}

	return uint(ids[0]), nil
}

func generateHashID(id uint) (string, error) {
	return getGlobalHashIDService().GenerateHashID(id)
}

func parseHashID(hashid string) (uint, error) {
	return getGlobalHashIDService().ParseHashID(hashid)
}

func NewUser(user *models.User, userService *UserService, passwordService *PasswordService, sessionService *SessionService, db *gorm.DB, domainCode string) (*User, error) {
	hashid, err := generateHashID(user.ID)
	if err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}

	return &User{
		User:            user,
		HashID:          hashid,
		passwordService: passwordService,
		sessionService:  sessionService,
		db:              db,
		domainCode:      domainCode,
	}, nil
}

func NewSession(session *models.Session) (*Session, error) {
	if session == nil {
		return nil, consts.VALIDATION_FAILED
	}

	// Debug: Log session details before generating hashid
	slog.Info("NewSession: Creating session object",
		"sessionID", session.ID,
		"userID", session.UserID,
		"domainCode", session.DomainCode,
		"createdAt", session.CreatedAt)

	hashid, err := generateHashID(session.ID)
	if err != nil {
		slog.Error("NewSession: Failed to generate hashid", "error", err, "sessionID", session.ID)
		return nil, consts.UNEXPECTED_FAILURE
	}

	slog.Info("NewSession: HashID generated successfully",
		"sessionID", session.ID,
		"hashID", hashid)

	return &Session{
		Session: session,
		HashID:  hashid,
	}, nil
}

func GetUserIDFromHashID(hashid string) (uint, error) {
	return parseHashID(hashid)
}

func GetSessionIDFromHashID(hashid string) (uint, error) {
	return parseHashID(hashid)
}

func GenerateUserHashID(userID uint) (string, error) {
	return generateHashID(userID)
}

func GenerateSessionHashID(sessionID uint) (string, error) {
	return generateHashID(sessionID)
}

func NewSSOProvider(ssoProvider *models.SSOProvider) (*SSOProvider, error) {
	if ssoProvider == nil {
		return nil, consts.VALIDATION_FAILED
	}

	hashid, err := generateHashID(ssoProvider.ID)
	if err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}

	return &SSOProvider{
		SSOProvider: ssoProvider,
		HashID:      hashid,
	}, nil
}

func NewSAMLProvider(samlProvider *models.SAMLProvider) (*SAMLProvider, error) {
	if samlProvider == nil {
		return nil, consts.VALIDATION_FAILED
	}

	hashid, err := generateHashID(samlProvider.ID)
	if err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}

	return &SAMLProvider{
		SAMLProvider: samlProvider,
		HashID:       hashid,
	}, nil
}

func GetSSOProviderIDFromHashID(hashid string) (uint, error) {
	return parseHashID(hashid)
}

func GetSAMLProviderIDFromHashID(hashid string) (uint, error) {
	return parseHashID(hashid)
}
