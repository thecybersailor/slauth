package registry

import (
	"fmt"

	"github.com/flaboy/aira-core/pkg/mailer"
	"github.com/thecybersailor/slauth/pkg/adapters"
	"github.com/thecybersailor/slauth/pkg/services"
	"gorm.io/gorm"
)

var authServices = make(map[string]services.AuthService)

func RegisterAuthService(instanceId, globalJWTSecret, globalAppSecret string, db *gorm.DB) services.AuthService {
	if _, exists := authServices[instanceId]; exists {
		panic(fmt.Sprintf("AuthService for instance '%s' already registered", instanceId))
	}
	authService := services.NewAuthServiceImpl(db, instanceId, globalJWTSecret, globalAppSecret)

	authService.SetEmailProvider(adapters.NewMailerAdapter(mailer.SMTPSender))

	authServices[instanceId] = authService
	return authService
}

func GetAuthService(instanceId string) services.AuthService {
	service, exists := authServices[instanceId]
	if !exists {
		panic(fmt.Sprintf("AuthService for instance '%s' not found", instanceId))
	}
	return service
}
