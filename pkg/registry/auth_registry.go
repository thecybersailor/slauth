package registry

import (
	"fmt"

	"github.com/flaboy/aira-core/pkg/mailer"
	"github.com/thecybersailor/slauth/pkg/adapters"
	"github.com/thecybersailor/slauth/pkg/services"
	"gorm.io/gorm"
)

var authServices = make(map[string]services.AuthService)

func RegisterAuthService(domainCode, globalJWTSecret, globalAppSecret string, db *gorm.DB) services.AuthService {
	if _, exists := authServices[domainCode]; exists {
		panic(fmt.Sprintf("AuthService for domain '%s' already registered", domainCode))
	}
	authService := services.NewAuthServiceImpl(db, domainCode, globalJWTSecret, globalAppSecret)

	authService.SetEmailProvider(adapters.NewMailerAdapter(mailer.SMTPSender))

	authServices[domainCode] = authService
	return authService
}

func GetAuthService(domainCode string) services.AuthService {
	service, exists := authServices[domainCode]
	if !exists {
		panic(fmt.Sprintf("AuthService for domain '%s' not found", domainCode))
	}
	return service
}
