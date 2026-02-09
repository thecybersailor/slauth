package services

import (
	"context"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/models"
)

type userCreatedContextImpl struct {
	context.Context
	authService AuthService
	httpRequest *http.Request

	user         *User        // After hook时有值
	userModel    *models.User // Before hook时使用
	source       UserCreatedSource
	opts         *UserCreateOptions
	extraContext map[string]any // 存储Provider、Identity等
	isBeforeHook bool

	response *UserCreatedResponse
}

func (u *userCreatedContextImpl) Service() AuthService {
	return u.authService
}

func (u *userCreatedContextImpl) HttpRequest() *http.Request {
	return u.httpRequest
}

func (u *userCreatedContextImpl) GetTrigger() FlowTrigger {
	if u.httpRequest != nil {
		return TriggerHttpRequest
	}
	return TriggerBackground
}

func (u *userCreatedContextImpl) User() *User {
	return u.user
}

func (u *userCreatedContextImpl) Source() UserCreatedSource {
	return u.source
}

func (u *userCreatedContextImpl) Provider() string {
	if u.extraContext != nil {
		if provider, ok := u.extraContext["provider"].(string); ok {
			return provider
		}
	}
	return ""
}

func (u *userCreatedContextImpl) Identity() *models.Identity {
	if u.extraContext != nil {
		if identity, ok := u.extraContext["identity"].(*models.Identity); ok {
			return identity
		}
	}
	return nil
}

func (u *userCreatedContextImpl) Response() *UserCreatedResponse {
	if u.response == nil {
		u.response = &UserCreatedResponse{
			User: u.user,
		}
	}
	return u.response
}

func (u *userCreatedContextImpl) UserMetadata() map[string]any {
	if u.opts != nil {
		return u.opts.UserMetadata
	}
	return nil
}

func (u *userCreatedContextImpl) SetUserMetadata(metadata map[string]any) {
	if u.opts != nil {
		u.opts.UserMetadata = metadata
	}
}
