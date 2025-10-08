package signup

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// signupContextImpl Implements services.SignupContext interface
type signupContextImpl struct {
	context.Context
	service     services.AuthService
	httpRequest *http.Request
	request     *types.SignUpRequest
	response    *services.SignupResponse
	trigger     services.FlowTrigger
}

func (s *signupContextImpl) Service() services.AuthService {
	return s.service
}

func (s *signupContextImpl) HttpRequest() *http.Request {
	return s.httpRequest
}

func (s *signupContextImpl) Request() *types.SignUpRequest {
	return s.request
}

func (s *signupContextImpl) Response() *services.SignupResponse {
	if s.response == nil {
		s.response = &services.SignupResponse{}
	}
	return s.response
}

func (s *signupContextImpl) GetTrigger() services.FlowTrigger {
	return s.trigger
}

// NewSignupContext Create new SignupContext
func NewSignupContext(ctx context.Context, service services.AuthService, httpRequest *http.Request, request *types.SignUpRequest) services.SignupContext {
	return &signupContextImpl{
		Context:     ctx,
		service:     service,
		httpRequest: httpRequest,
		request:     request,
		trigger:     services.TriggerHttpRequest, // Default to HTTP request trigger
	}
}

// CreateUserFlow Create user flow
func CreateUserFlow(signupCtx services.SignupContext) core.Flow[core.SignupData] {
	return func(ctx *core.Context[core.SignupData], next func() error) error {
		slog.Info("Flow: CreateUser - Before")

		// Create user
		user, err := signupCtx.Service().GetUserService().CreateWithMetadata(
			signupCtx,
			ctx.Data.Email,
			ctx.Data.Phone,
			ctx.Data.Password,
			ctx.Data.UserData,
			nil, // appMetadata
		)
		if err != nil {
			slog.Error("Flow: CreateUser - Failed to create user", "error", err)
			return err
		}

		// Store user ID to context
		ctx.Data.UserID = fmt.Sprintf("%d", user.ID)
		ctx.User = user

		// Store user to SignupContext response
		signupCtx.Response().User = user

		slog.Info("Flow: CreateUser - User created", "userID", user.ID)

		return next()
	}
}

// GenerateConfirmationURLFlow Generate confirmation link flow
func GenerateConfirmationURLFlow(signupCtx services.SignupContext) core.Flow[core.SignupData] {
	return func(ctx *core.Context[core.SignupData], next func() error) error {
		slog.Info("Flow: GenerateConfirmationURL - Before")

		// Ensure user is created
		if signupCtx.Response().User == nil {
			return fmt.Errorf("user not found in signup context")
		}

		// Get user directly from SignupContext, no type assertion needed
		userObj := signupCtx.Response().User
		user := userObj.User

		// Generate real confirmation token
		confirmationToken, tokenHash, err := services.GenerateConfirmationToken()
		if err != nil {
			slog.Error("Flow: GenerateConfirmationURL - Failed to generate token", "error", err)
			return fmt.Errorf("failed to generate confirmation token: %w", err)
		}

		// Create OneTimeToken record
		otToken := &models.OneTimeToken{
			UserID:     &user.ID,
			TokenType:  types.OneTimeTokenTypeConfirmation,
			TokenHash:  tokenHash,
			RelatesTo:  signupCtx.Request().Email, // Associate with email address
			InstanceId: signupCtx.Service().GetInstanceId(),
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		// Get OneTimeTokenService and store token
		authServiceImpl, ok := signupCtx.Service().(*services.AuthServiceImpl)
		if !ok {
			return fmt.Errorf("invalid auth service type")
		}

		otTokenService := authServiceImpl.GetOneTimeTokenService()
		if err := otTokenService.Create(signupCtx, otToken); err != nil {
			slog.Error("Flow: GenerateConfirmationURL - Failed to store token", "error", err)
			return fmt.Errorf("failed to store confirmation token: %w", err)
		}

		// Generate confirmation URL
		confirmationURL := fmt.Sprintf("%s/confirm?token=%s", signupCtx.Service().GetConfig().AuthServiceBaseUrl, confirmationToken)

		// Store confirmation URL to context for email template use
		if ctx.Data.UserData == nil {
			ctx.Data.UserData = make(map[string]interface{})
		}
		ctx.Data.UserData["ConfirmationURL"] = confirmationURL

		// Store confirmation URL to SignupContext response
		signupCtx.Response().ConfirmationURL = confirmationURL

		slog.Info("Flow: GenerateConfirmationURL - URL generated",
			"url", confirmationURL,
			"userID", user.ID,
			"tokenType", types.OneTimeTokenTypeConfirmation)

		return next()
	}
}

// SendConfirmationEmailFlow Send confirmation email flow
func SendConfirmationEmailFlow(signupCtx services.SignupContext) core.Flow[core.SignupData] {
	return core.EmailFlow[core.SignupData](
		core.EmailFlowConfig{
			AuthService:   signupCtx.Service(),
			EmailProvider: signupCtx.Service().GetEmailProvider(),
			TemplateName:  "confirm-signup",
			MessageType:   "email",
			InstanceId:    signupCtx.Service().GetInstanceId(),
		},
		func(data core.SignupData) string {
			return data.Email
		},
		func(data core.SignupData) map[string]interface{} {
			return data.UserData
		},
	)
}

// SendConfirmationSMSFlow Send confirmation SMS flow
func SendConfirmationSMSFlow(signupCtx services.SignupContext) core.Flow[core.SignupData] {
	return core.SMSFlow[core.SignupData](
		core.SMSFlowConfig{
			AuthService:  signupCtx.Service(),
			SMSProvider:  signupCtx.Service().GetSMSProvider(),
			TemplateName: "reauthentication",
			MessageType:  "sms",
			InstanceId:   signupCtx.Service().GetInstanceId(),
		},
		func(data core.SignupData) string {
			return data.Phone
		},
		func(data core.SignupData) map[string]interface{} {
			return data.UserData
		},
	)
}

// ExecuteSignupMiddlewaresFlow Execute signup flow middlewares
func ExecuteSignupMiddlewaresFlow(signupCtx services.SignupContext) core.Flow[core.SignupData] {
	return func(ctx *core.Context[core.SignupData], next func() error) error {
		slog.Info("Flow: ExecuteSignupMiddlewares - Before")

		// Get AuthService implementation to access middleware
		authServiceImpl, ok := signupCtx.Service().(*services.AuthServiceImpl)
		if !ok {
			slog.Warn("Flow: ExecuteSignupMiddlewares - AuthService is not AuthServiceImpl, skipping middlewares")
			return next()
		}

		// Get all signup middlewares
		middlewares := authServiceImpl.GetSignupMiddlewares()
		if len(middlewares) == 0 {
			slog.Info("Flow: ExecuteSignupMiddlewares - No middlewares to execute")
			return next()
		}

		// Create middleware execution chain
		var executeMiddleware func(index int) error
		executeMiddleware = func(index int) error {
			if index >= len(middlewares) {
				// All middlewares executed, continue to next flow
				return next()
			}

			// Execute current middleware
			middleware := middlewares[index]
			return middleware(signupCtx, func() error {
				// Execute next middleware
				return executeMiddleware(index + 1)
			})
		}

		// Start executing from first middleware
		return executeMiddleware(0)
	}
}

// CreateSignupChain Create signup business flow chain
func CreateSignupChain(request *http.Request, signupCtx services.SignupContext) *core.Chain[core.SignupData] {
	chain := core.NewChain[core.SignupData](
		core.LoggingFlow[core.SignupData](),
		ExecuteSignupMiddlewaresFlow(signupCtx), // Execute middlewares
		CreateUserFlow(signupCtx),
	)

	// Only add confirmation flows if email confirmation is enabled
	config := signupCtx.Service().GetConfig()
	if config.ConfirmEmail != nil && *config.ConfirmEmail {
		chain.Use(GenerateConfirmationURLFlow(signupCtx))
		chain.Use(SendConfirmationEmailFlow(signupCtx))
		// SendConfirmationSMSFlow(signupCtx), // Enable if SMS sending is needed
	}

	return chain
}
