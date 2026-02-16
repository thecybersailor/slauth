package otp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type otpContextImpl struct {
	context.Context
	service     services.AuthService
	httpRequest *http.Request
	request     *types.SendOTPRequest
	response    *services.OTPResponse
	trigger     services.FlowTrigger
}

func (o *otpContextImpl) Service() services.AuthService {
	return o.service
}

func (o *otpContextImpl) HttpRequest() *http.Request {
	return o.httpRequest
}

func (o *otpContextImpl) Request() *types.SendOTPRequest {
	return o.request
}

func (o *otpContextImpl) Response() *services.OTPResponse {
	if o.response == nil {
		o.response = &services.OTPResponse{}
	}
	return o.response
}

func (o *otpContextImpl) GetTrigger() services.FlowTrigger {
	return o.trigger
}

func NewOTPContext(ctx context.Context, service services.AuthService, httpRequest *http.Request, request *types.SendOTPRequest) services.OTPContext {
	return &otpContextImpl{
		Context:     ctx,
		service:     service,
		httpRequest: httpRequest,
		request:     request,
		trigger:     services.TriggerHttpRequest,
	}
}

type OTPData struct {
	Email string                 `json:"email"`
	Phone string                 `json:"phone"`
	Code  string                 `json:"code"`
	Data  map[string]interface{} `json:"data"`
}

func GenerateOTPFlow(ctx services.OTPContext, next func() error) error {
	req := ctx.Request()

	code, err := ctx.Service().GenerateOTPCode(ctx)
	if err != nil {
		return err
	}

	authServiceImpl, ok := ctx.Service().(*services.AuthServiceImpl)
	if !ok {
		return fmt.Errorf("invalid auth service type")
	}

	otpService := authServiceImpl.GetOTPService()
	db := authServiceImpl.GetDB()
	instanceId := ctx.Service().GetInstanceId()

	tokenType := types.OneTimeTokenTypeConfirmation

	sessionCode, err := otpService.StoreOTP(ctx, req.Email, req.Phone, code, tokenType, instanceId, db)
	if err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	ctx.Response().Code = code
	ctx.Response().MessageID = "otp-generated"
	ctx.Response().SessionCode = sessionCode

	return next()
}

func SendOTPEmailFlow(ctx services.OTPContext, next func() error) error {
	req := ctx.Request()
	response := ctx.Response()

	if req.Email == "" {
		return next()
	}

	subject := "Your verification code"
	body := fmt.Sprintf("Your verification code is: %s", response.Code)
	messageID, err := ctx.Service().GetEmailProvider().SendEmail(ctx, req.Email, subject, body)
	if err != nil {
		return err
	}
	if messageID != nil {
		response.MessageID = *messageID
	} else {
		response.MessageID = "email-otp-sent"
	}
	return next()
}

func SendOTPSMSFlow(ctx services.OTPContext, next func() error) error {
	req := ctx.Request()
	response := ctx.Response()

	if req.Phone == "" {
		return next()
	}

	message := fmt.Sprintf("Your verification code is: %s", response.Code)
	messageID, err := ctx.Service().GetSMSProvider().SendSMS(ctx, req.Phone, message)
	if err != nil {
		return err
	}
	if messageID != nil {
		response.MessageID = *messageID
	} else {
		response.MessageID = "sms-otp-sent"
	}
	return next()
}

func CreateOTPChain(ctx services.OTPContext) services.FlowChain {
	chain := services.NewFlowChain()

	if authServiceImpl, ok := ctx.Service().(*services.AuthServiceImpl); ok {
		middlewares := authServiceImpl.GetOTPMiddlewares()
		for i, middleware := range middlewares {
			chain.Add(fmt.Sprintf("middleware_%d", i), middleware)
		}
	}

	chain.Add("generate", GenerateOTPFlow)
	chain.Add("send_email", SendOTPEmailFlow)
	chain.Add("send_sms", SendOTPSMSFlow)

	return chain
}
