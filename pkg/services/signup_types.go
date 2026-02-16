package services

import (
	"context"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/models"
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
	Code        string
	Success     bool
	Message     string
	MessageID   string
	SessionCode string
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

// UserCreatedSource 用户创建来源
type UserCreatedSource string

const (
	UserCreatedSourceSignup    UserCreatedSource = "signup"
	UserCreatedSourceOAuth     UserCreatedSource = "oauth"
	UserCreatedSourceAdmin     UserCreatedSource = "admin"
	UserCreatedSourceInvite    UserCreatedSource = "invite"
	UserCreatedSourceMagicLink UserCreatedSource = "magic_link"
)

type UserCreatedResponse struct {
	User *User
}

type UserCreatedContext interface {
	FlowInterface
	User() *User                // 用户对象（Before时ID=0，After时ID已分配）
	Source() UserCreatedSource  // 创建来源
	Provider() string           // OAuth provider（仅OAuth场景）
	Identity() *models.Identity // OAuth identity（仅OAuth场景）
	Response() *UserCreatedResponse

	// 用于Before hook修改用户数据
	UserMetadata() map[string]any
	SetUserMetadata(map[string]any)
}

// AuthMethod 认证方法
type AuthMethod string

const (
	AuthMethodPassword  AuthMethod = "password"
	AuthMethodOAuth     AuthMethod = "oauth"
	AuthMethodMagicLink AuthMethod = "magic_link"
	AuthMethodOTP       AuthMethod = "otp"
)

type AuthenticatedResponse struct {
	User    *User
	Session *Session
}

type AuthenticatedContext interface {
	FlowInterface
	User() *User
	Method() AuthMethod
	Provider() string // OAuth/MFA provider名称
	Response() *AuthenticatedResponse
}

type SessionCreatedResponse struct {
	Session      *Session
	AccessToken  string
	RefreshToken string
}

type SessionCreatedContext interface {
	FlowInterface
	User() *User
	Session() *Session
	Response() *SessionCreatedResponse
}

type IdentityLinkedResponse struct {
	Identity *models.Identity
}

type IdentityLinkedContext interface {
	FlowInterface
	User() *User
	Provider() string
	Identity() *models.Identity
	IsNewIdentity() bool // true=新创建，false=已存在
	Response() *IdentityLinkedResponse
}
