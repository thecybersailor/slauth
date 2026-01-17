package services

import (
	"context"
	"net/http"
)

type sessionCreatedContextImpl struct {
	context.Context
	authService AuthService
	httpRequest *http.Request

	user         *User
	session      *Session
	accessToken  string
	refreshToken string

	response *SessionCreatedResponse
}

func (s *sessionCreatedContextImpl) Service() AuthService {
	return s.authService
}

func (s *sessionCreatedContextImpl) HttpRequest() *http.Request {
	return s.httpRequest
}

func (s *sessionCreatedContextImpl) GetTrigger() FlowTrigger {
	if s.httpRequest != nil {
		return TriggerHttpRequest
	}
	return TriggerBackground
}

func (s *sessionCreatedContextImpl) User() *User {
	return s.user
}

func (s *sessionCreatedContextImpl) Session() *Session {
	return s.session
}

func (s *sessionCreatedContextImpl) Response() *SessionCreatedResponse {
	if s.response == nil {
		s.response = &SessionCreatedResponse{
			Session:      s.session,
			AccessToken:  s.accessToken,
			RefreshToken: s.refreshToken,
		}
	}
	return s.response
}
