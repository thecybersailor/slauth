package signin

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// signinContextImpl Implements services.SigninContext interface
type signinContextImpl struct {
	context.Context
	service     services.AuthService
	httpRequest *http.Request
	request     *types.SignInWithPasswordRequest
	response    *services.SigninResponse
	trigger     services.FlowTrigger
}

func (s *signinContextImpl) Service() services.AuthService {
	return s.service
}

func (s *signinContextImpl) HttpRequest() *http.Request {
	return s.httpRequest
}

func (s *signinContextImpl) Request() *types.SignInWithPasswordRequest {
	return s.request
}

func (s *signinContextImpl) Response() *services.SigninResponse {
	if s.response == nil {
		s.response = &services.SigninResponse{}
	}
	return s.response
}

func (s *signinContextImpl) GetTrigger() services.FlowTrigger {
	return s.trigger
}

// NewSigninContext Create new SigninContext
func NewSigninContext(ctx context.Context, service services.AuthService, httpRequest *http.Request, request *types.SignInWithPasswordRequest) services.SigninContext {
	return &signinContextImpl{
		Context:     ctx,
		service:     service,
		httpRequest: httpRequest,
		request:     request,
		trigger:     services.TriggerHttpRequest, // Default to HTTP request trigger
	}
}

// AuthenticateUserFlow Authenticate user flow
func AuthenticateUserFlow(signinCtx services.SigninContext) core.Flow[core.SigninData] {
	return func(ctx *core.Context[core.SigninData], next func() error) error {
		slog.Info("Flow: AuthenticateUser - Before")

		// Authenticate user
		user, err := signinCtx.Service().AuthenticateUser(
			signinCtx,
			ctx.Data.EmailOrPhone,
			ctx.Data.Password,
		)
		if err != nil {
			slog.Error("Flow: AuthenticateUser - Authentication failed", "error", err)
			return err
		}

		// Store user info to context
		ctx.Data.UserID = user.HashID // Use hash ID instead of numeric ID
		ctx.User = user

		// Store user to SigninContext response
		signinCtx.Response().User = user

		slog.Info("Flow: AuthenticateUser - User authenticated", "userID", user.User.ID)

		return next()
	}
}

// CreateSessionFlow Create session flow
func CreateSessionFlow(signinCtx services.SigninContext) core.Flow[core.SigninData] {
	return func(ctx *core.Context[core.SigninData], next func() error) error {
		slog.Info("Flow: CreateSession - Before")

		// Ensure user is authenticated
		user := signinCtx.Response().User
		if user == nil {
			return fmt.Errorf("user not found in signin context")
		}

		// Get user agent and IP from HTTP request
		userAgent := signinCtx.HttpRequest().UserAgent()
		ip := signinCtx.HttpRequest().RemoteAddr

		// Create session
		session, accessToken, refreshToken, expiresIn, err := signinCtx.Service().CreateSession(
			signinCtx,
			user,
			types.AALLevel1, // Basic authentication level
			[]string{"password"},
			userAgent,
			ip,
		)
		if err != nil {
			slog.Error("Flow: CreateSession - Failed to create session", "error", err)
			return err
		}

		// Store session info to context
		ctx.Data.SessionID = session.HashID
		ctx.Data.AccessToken = accessToken
		ctx.Data.RefreshToken = refreshToken
		ctx.Data.ExpiresIn = expiresIn

		// Store session info to SigninContext response
		signinCtx.Response().Session = session
		signinCtx.Response().AccessToken = accessToken
		signinCtx.Response().RefreshToken = refreshToken
		signinCtx.Response().ExpiresIn = expiresIn

		slog.Info("Flow: CreateSession - Session created",
			"sessionID", session.Session.ID,
			"sessionHashID", session.HashID,
			"userID", user.User.ID,
			"expiresIn", expiresIn)

		return next()
	}
}

// SendOTPFlow Send OTP flow
func SendOTPFlow(signinCtx services.SigninContext) core.Flow[core.SigninData] {
	return core.SMSFlow[core.SigninData](
		core.SMSFlowConfig{
			AuthService:  signinCtx.Service(),
			SMSProvider:  signinCtx.Service().GetSMSProvider(),
			TemplateName: "verification-code",
			MessageType:  "sms",
			DomainCode:   signinCtx.Service().GetDomainCode(),
		},
		func(data core.SigninData) string {
			return data.EmailOrPhone
		},
		func(data core.SigninData) map[string]interface{} {
			return map[string]interface{}{
				"Token": "dummy_otp_token", // TODO: Generate real OTP token
			}
		},
	)
}

// CreatePasswordSigninChain Create password signin flow chain
func CreatePasswordSigninChain(request *http.Request, signinCtx services.SigninContext) *core.Chain[core.SigninData] {
	return core.NewChain[core.SigninData](
		core.LoggingFlow[core.SigninData](),
		AuthenticateUserFlow(signinCtx),
		CreateSessionFlow(signinCtx),
	)
}

// CreateOTPSigninChain Create OTP signin flow chain
func CreateOTPSigninChain(request *http.Request, signinCtx services.SigninContext) *core.Chain[core.SigninData] {
	return core.NewChain[core.SigninData](
		core.LoggingFlow[core.SigninData](),
		SendOTPFlow(signinCtx),
	)
}
