package services

import (
	"net/url"
	"strings"

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

	// Allow same instance redirects automatically
	if r.isSameInstance(redirect_to) {
		return redirect_to
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

	// Allow same instance redirects automatically
	if r.isSameInstance(redirect_to) {
		return redirect_to, nil
	}

	if err := r.validator.ValidateRedirectURL(redirect_to, r.config.RedirectURLs); err != nil {
		return "", consts.VALIDATION_FAILED
	}

	return redirect_to, nil
}

// isSameInstance checks if redirect_to is the same instance as SiteURL
func (r *RedirectService) isSameInstance(redirect_to string) bool {
	// Relative paths are always same instance
	if strings.HasPrefix(redirect_to, "/") {
		return true
	}

	// Parse both URLs
	siteURL, err := url.Parse(r.config.SiteURL)
	if err != nil {
		return false
	}

	redirectURL, err := url.Parse(redirect_to)
	if err != nil {
		return false
	}

	// Compare scheme and host
	return siteURL.Scheme == redirectURL.Scheme && siteURL.Host == redirectURL.Host
}
