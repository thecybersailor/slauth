package services

import (
	"net/url"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/types"
)

func emailActionURL(siteURL string, purpose types.EmailActionPurpose, token string) (string, error) {
	paths := map[types.EmailActionPurpose]string{
		types.EmailActionPurposeRecovery:    "/reset-password",
		types.EmailActionPurposeEmailChange: "/change-email",
	}
	path, ok := paths[purpose]
	if !ok || token == "" {
		return "", consts.VALIDATION_FAILED
	}
	u, err := url.Parse(siteURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", consts.VALIDATION_FAILED
	}
	u.Path = path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = url.Values{"token": []string{token}}.Encode()
	return u.String(), nil
}
