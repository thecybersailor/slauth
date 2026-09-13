package controller

import (
	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

func (a *AuthController) StartEmailSignup(c *pin.Context) error {
	req := &types.EmailSignupStartRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}
	signup, err := a.newEmailSignupService()
	if err != nil {
		return err
	}
	resp, err := signup.Start(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		return err
	}
	return c.Render(resp)
}

func (a *AuthController) ResendEmailSignup(c *pin.Context) error {
	req := &types.EmailSignupResendRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}
	signup, err := a.newEmailSignupService()
	if err != nil {
		return err
	}
	resp, err := signup.Resend(c.Request.Context(), req.ChallengeID)
	if err != nil {
		return err
	}
	return c.Render(resp)
}

func (a *AuthController) newEmailSignupService() (*services.EmailSignupService, error) {
	authServiceImpl, ok := a.authService.(*services.AuthServiceImpl)
	if !ok {
		return nil, consts.UNEXPECTED_FAILURE
	}
	emailActions := services.NewEmailActionService(a.authService.GetDB(), a.authService.GetConfig().AppSecret)
	return services.NewEmailSignupService(
		a.authService.GetDB(),
		a.authService.GetInstanceId(),
		a.authService.GetPasswordService(),
		emailActions,
		authServiceImpl.GetEmailProvider(),
	), nil
}
