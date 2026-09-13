package controller

import (
	"github.com/flaboy/pin"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

func (u *UserController) StartEmailChangeLink(c *pin.Context) error {
	req := &StartEmailChangeRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}
	user, currentAAL, err := u.getCurrentUserAndAAL(c)
	if err != nil {
		return err
	}
	sessionID, err := u.extractSessionIDFromToken(c)
	if err != nil {
		return err
	}
	if err := services.NewEmailChangeLinkService(u.authService).Start(c.Request.Context(), user, sessionID, currentAAL, req.Email); err != nil {
		return err
	}
	return c.Render(map[string]string{"message": "Email change confirmation sent."})
}

func (u *UserController) CompleteEmailChangeLink(c *pin.Context) error {
	req := &types.EmailChangeCompleteRequest{}
	if err := c.BindJSON(req); err != nil {
		return consts.BAD_JSON
	}
	user, currentAAL, err := u.getCurrentUserAndAAL(c)
	if err != nil {
		return err
	}
	sessionID, err := u.extractSessionIDFromToken(c)
	if err != nil {
		return err
	}
	if err := services.NewEmailChangeLinkService(u.authService).Complete(c.Request.Context(), user, sessionID, currentAAL, req.Token); err != nil {
		return err
	}
	return c.Render(&types.EmailActionSuccessResponse{Success: true})
}
