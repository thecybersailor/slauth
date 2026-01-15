package registry

import (
	"fmt"

	"github.com/flaboy/aira-core/pkg/mailer"
	"github.com/thecybersailor/slauth/pkg/adapters"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

var authServices = make(map[string]services.AuthService)

// GetOrCreateAuthService lazily creates and returns an auth service for the instance
func GetOrCreateAuthService(instanceId string, secretsProvider types.InstanceSecretsProvider, db *gorm.DB) (services.AuthService, error) {
	if service, exists := authServices[instanceId]; exists {
		return service, nil
	}

	// Create new service
	authService := services.NewAuthServiceImpl(db, secretsProvider, instanceId)
	authService.SetEmailProvider(adapters.NewMailerAdapter(mailer.SMTPSender))

	authServices[instanceId] = authService
	return authService, nil
}

// GetOrCreateAuthServiceWithPasswordService lazily creates and returns an auth service with custom password service
func GetOrCreateAuthServiceWithPasswordService(instanceId string, secretsProvider types.InstanceSecretsProvider, passwordService *services.PasswordService, db *gorm.DB) (services.AuthService, error) {
	if service, exists := authServices[instanceId]; exists {
		return service, nil
	}

	// Create new service with custom password service
	authService := services.NewAuthServiceImplWithPasswordService(db, secretsProvider, instanceId, passwordService)
	authService.SetEmailProvider(adapters.NewMailerAdapter(mailer.SMTPSender))

	authServices[instanceId] = authService
	return authService, nil
}

// Deprecated: Use GetOrCreateAuthService with InstanceSecretsProvider
func RegisterAuthService(instanceId, globalJWTSecret, globalAppSecret string, db *gorm.DB) services.AuthService {
	if _, exists := authServices[instanceId]; exists {
		panic(fmt.Sprintf("AuthService for instance '%s' already registered", instanceId))
	}

	// Create a static secrets provider for backward compatibility
	secretsProvider := services.NewStaticSecretsProvider(&types.InstanceSecrets{
		PrimaryKeyId: "legacy-key",
		Keys: map[string]*types.SigningKey{
			"legacy-key": {
				Kid:        "legacy-key",
				Algorithm:  types.SignAlgES256, // Default to ES256
				PrivateKey: "",                 // Empty for legacy HS256 mode
				PublicKey:  "",                 // Empty for legacy HS256 mode
			},
		},
		AppSecret: globalAppSecret,
	})

	authService := services.NewAuthServiceImpl(db, secretsProvider, instanceId)
	authService.SetEmailProvider(adapters.NewMailerAdapter(mailer.SMTPSender))

	authServices[instanceId] = authService
	return authService
}

// Deprecated: Use GetOrCreateAuthServiceWithPasswordService with InstanceSecretsProvider
func RegisterAuthServiceWithPasswordService(instanceId, globalJWTSecret, globalAppSecret string, passwordService *services.PasswordService, db *gorm.DB) services.AuthService {
	if _, exists := authServices[instanceId]; exists {
		panic(fmt.Sprintf("AuthService for instance '%s' already registered", instanceId))
	}

	// Create a static secrets provider for backward compatibility
	secretsProvider := services.NewStaticSecretsProvider(&types.InstanceSecrets{
		PrimaryKeyId: "legacy-key",
		Keys: map[string]*types.SigningKey{
			"legacy-key": {
				Kid:        "legacy-key",
				Algorithm:  types.SignAlgES256, // Default to ES256
				PrivateKey: "",                 // Empty for legacy HS256 mode
				PublicKey:  "",                 // Empty for legacy HS256 mode
			},
		},
		AppSecret: globalAppSecret,
	})

	authService := services.NewAuthServiceImplWithPasswordService(db, secretsProvider, instanceId, passwordService)
	authService.SetEmailProvider(adapters.NewMailerAdapter(mailer.SMTPSender))

	authServices[instanceId] = authService
	return authService
}

func GetAuthService(instanceId string) (services.AuthService, error) {
	service, exists := authServices[instanceId]
	if !exists {
		return nil, fmt.Errorf("AuthService for instance '%s' not found", instanceId)
	}
	return service, nil
}
