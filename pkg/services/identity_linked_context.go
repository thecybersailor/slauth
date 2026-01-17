package services

import (
	"context"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/models"
)

type identityLinkedContextImpl struct {
	context.Context
	authService AuthService
	httpRequest *http.Request

	user          *User
	provider      string
	identity      *models.Identity
	isNewIdentity bool

	response *IdentityLinkedResponse
}

func (i *identityLinkedContextImpl) Service() AuthService {
	return i.authService
}

func (i *identityLinkedContextImpl) HttpRequest() *http.Request {
	return i.httpRequest
}

func (i *identityLinkedContextImpl) GetTrigger() FlowTrigger {
	if i.httpRequest != nil {
		return TriggerHttpRequest
	}
	return TriggerBackground
}

func (i *identityLinkedContextImpl) User() *User {
	return i.user
}

func (i *identityLinkedContextImpl) Provider() string {
	return i.provider
}

func (i *identityLinkedContextImpl) Identity() *models.Identity {
	return i.identity
}

func (i *identityLinkedContextImpl) IsNewIdentity() bool {
	return i.isNewIdentity
}

func (i *identityLinkedContextImpl) Response() *IdentityLinkedResponse {
	if i.response == nil {
		i.response = &IdentityLinkedResponse{
			Identity: i.identity,
		}
	}
	return i.response
}
