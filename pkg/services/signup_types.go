package services

import (
	"context"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/types"
)

type FlowTrigger string

const (
	TriggerHttpRequest FlowTrigger = "http_request"
	TriggerBackground  FlowTrigger = "background"
)

// SignupRequest = types.SignUpRequest
// PasswordRequest = types.ResetPasswordRequest

type SignupResponse struct {
	User            *User
	Session         *Session
	AccessToken     string
	RefreshToken    string
	ExpiresIn       int64
	ConfirmationURL string
}

type FlowInterface interface {
	context.Context
	GetTrigger() FlowTrigger
	Service() AuthService
	HttpRequest() *http.Request

	// SetTrigger(trigger FlowTrigger)
	// SetService(service AuthService)
	// SetRequest(request *http.Request)
}

type SignupContext interface {
	FlowInterface
	Request() *types.SignUpRequest
	Response() *SignupResponse
}

type SigninResponse struct {
	User         *User
	Session      *Session
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type SigninContext interface {
	FlowInterface
	Request() *types.SignInWithPasswordRequest
	Response() *SigninResponse
}

type PasswordResponse struct {
	ResetURL string
	Token    string
	Success  bool
}

type PasswordUpdateResponse struct {
	Success bool
	Message string
}

type PasswordContext interface {
	FlowInterface
	Request() *types.ResetPasswordRequest
	Response() *PasswordResponse
}

type PasswordUpdateContext interface {
	FlowInterface
	Request() *types.UpdatePasswordRequest
	Response() *PasswordUpdateResponse
	UserID() string
}

type OTPResponse struct {
	Code      string
	Success   bool
	Message   string
	MessageID string
}

type OTPContext interface {
	FlowInterface
	Request() *types.SendOTPRequest
	Response() *OTPResponse
}

type FlowChain interface {
	Add(name string, flow func(ctx OTPContext, next func() error) error) FlowChain
	Execute(ctx OTPContext) error
}

type flowChainImpl struct {
	flows []func(ctx OTPContext, next func() error) error
}

func NewFlowChain() FlowChain {
	return &flowChainImpl{
		flows: make([]func(ctx OTPContext, next func() error) error, 0),
	}
}

func (fc *flowChainImpl) Add(name string, flow func(ctx OTPContext, next func() error) error) FlowChain {
	fc.flows = append(fc.flows, flow)
	return fc
}

func (fc *flowChainImpl) Execute(ctx OTPContext) error {
	var next func() error
	index := -1

	next = func() error {
		index++
		if index < len(fc.flows) {
			return fc.flows[index](ctx, next)
		}
		return nil
	}

	return next()
}
