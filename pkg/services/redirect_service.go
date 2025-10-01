package services

import (
	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
)

// RedirectService handles redirect URL validation and processing
type RedirectService struct {
	config    *config.AuthServiceConfig
	validator *ValidatorService
}

// NewRedirectService creates a new redirect service
func NewRedirectService(config *config.AuthServiceConfig, validator *ValidatorService) *RedirectService {
	return &RedirectService{
		config:    config,
		validator: validator,
	}
}

// ValidateAndGetRedirectTo validates redirect URL and returns safe URL
// If invalid or empty, returns SiteURL as fallback
func (r *RedirectService) ValidateAndGetRedirectTo(redirect_to string) string {
	if redirect_to == "" {
		return r.config.SiteURL
	}

	// Validate against whitelist
	if err := r.validator.ValidateRedirectURL(redirect_to, r.config.RedirectURLs); err != nil {
		// Invalid URL, return default
		return r.config.SiteURL
	}

	return redirect_to
}

// ValidateAndGetRedirectToOrError validates and returns error if invalid
func (r *RedirectService) ValidateAndGetRedirectToOrError(redirect_to string) (string, error) {
	if redirect_to == "" {
		return r.config.SiteURL, nil
	}

	if err := r.validator.ValidateRedirectURL(redirect_to, r.config.RedirectURLs); err != nil {
		return "", consts.VALIDATION_FAILED
	}

	return redirect_to, nil
}
