package services

import (
	"log/slog"
	"sync/atomic"

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

var globalHashIDService atomic.Value // *HashIDService

func SetGlobalHashIDService(service *HashIDService) {
	if service == nil {
		return
	}
	if existing := getGlobalHashIDServiceMaybeNil(); existing != nil && existing.appSecret != service.appSecret {
		// NOTE: Multi-instance apps may create multiple AuthServiceImpl with different AppSecret.
		// A single process-wide global cannot represent multiple secrets. To avoid subtle breakage,
		// we keep the first one and ignore subsequent different secrets.
		slog.Warn("SetGlobalHashIDService ignored: already set with different appSecret")
		return
	}
	globalHashIDService.Store(service)
}

func getGlobalHashIDServiceMaybeNil() *HashIDService {
	if v := globalHashIDService.Load(); v != nil {
		if s, ok := v.(*HashIDService); ok {
			return s
		}
	}
	return nil
}

func getGlobalHashIDService() *HashIDService {
	if s := getGlobalHashIDServiceMaybeNil(); s != nil {
		return s
	}
	return &HashIDService{appSecret: ""}
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

func resolveHashIDService(service *HashIDService) *HashIDService {
	if service != nil {
		return service
	}
	return getGlobalHashIDService()
}

func generateHashIDWithService(service *HashIDService, id uint) (string, error) {
	return resolveHashIDService(service).GenerateHashID(id)
}

func parseHashIDWithService(service *HashIDService, hashid string) (uint, error) {
	return resolveHashIDService(service).ParseHashID(hashid)
}

func generateHashID(id uint) (string, error) {
	return generateHashIDWithService(nil, id)
}

func parseHashID(hashid string) (uint, error) {
	return parseHashIDWithService(nil, hashid)
}

func NewUser(user *models.User, userService *UserService, passwordService *PasswordService, sessionService *SessionService, db *gorm.DB, instanceId string) (*User, error) {
	return NewUserWithHashIDService(nil, user, userService, passwordService, sessionService, db, instanceId)
}

func NewUserWithHashIDService(hashIDService *HashIDService, user *models.User, userService *UserService, passwordService *PasswordService, sessionService *SessionService, db *gorm.DB, instanceId string) (*User, error) {
	svc := resolveHashIDService(hashIDService)
	hashid, err := svc.GenerateHashID(user.ID)
	if err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}

	return &User{
		User:            user,
		HashID:          hashid,
		passwordService: passwordService,
		sessionService:  sessionService,
		db:              db,
		instanceId:      instanceId,
		hashIDService:   svc,
	}, nil
}

func NewSession(session *models.Session) (*Session, error) {
	return NewSessionWithHashIDService(nil, session)
}

func NewSessionWithHashIDService(hashIDService *HashIDService, session *models.Session) (*Session, error) {
	if session == nil {
		return nil, consts.VALIDATION_FAILED
	}

	// Debug: Log session details before generating hashid
	slog.Info("NewSession: Creating session object",
		"sessionID", session.ID,
		"userID", session.UserID,
		"instanceId", session.InstanceId,
		"createdAt", session.CreatedAt)

	hashid, err := generateHashID(session.ID)
	if hashIDService != nil {
		hashid, err = generateHashIDWithService(hashIDService, session.ID)
	}
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

func GetUserIDFromHashIDWithHashIDService(hashIDService *HashIDService, hashid string) (uint, error) {
	return parseHashIDWithService(hashIDService, hashid)
}

func GetSessionIDFromHashIDWithHashIDService(hashIDService *HashIDService, hashid string) (uint, error) {
	return parseHashIDWithService(hashIDService, hashid)
}

func GenerateUserHashIDWithHashIDService(hashIDService *HashIDService, userID uint) (string, error) {
	return generateHashIDWithService(hashIDService, userID)
}

func GenerateSessionHashIDWithHashIDService(hashIDService *HashIDService, sessionID uint) (string, error) {
	return generateHashIDWithService(hashIDService, sessionID)
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
