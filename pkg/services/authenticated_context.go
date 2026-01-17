package services

import (
	"context"
	"net/http"
)

type authenticatedContextImpl struct {
	context.Context
	authService AuthService
	httpRequest *http.Request

	user     *User
	method   AuthMethod
	provider string

	response *AuthenticatedResponse
}

func (a *authenticatedContextImpl) Service() AuthService {
	return a.authService
}

func (a *authenticatedContextImpl) HttpRequest() *http.Request {
	return a.httpRequest
}

func (a *authenticatedContextImpl) GetTrigger() FlowTrigger {
	if a.httpRequest != nil {
		return TriggerHttpRequest
	}
	return TriggerBackground
}

func (a *authenticatedContextImpl) User() *User {
	return a.user
}

func (a *authenticatedContextImpl) Method() AuthMethod {
	return a.method
}

func (a *authenticatedContextImpl) Provider() string {
	return a.provider
}

func (a *authenticatedContextImpl) Response() *AuthenticatedResponse {
	if a.response == nil {
		a.response = &AuthenticatedResponse{
			User:    a.user,
			Session: nil, // 可能为nil，取决于调用时机
		}
	}
	return a.response
}
