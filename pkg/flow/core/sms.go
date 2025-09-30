package core

import (
	"context"
	"log/slog"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type SMSFlowConfig struct {
	AuthService  services.AuthService
	SMSProvider  types.SMSProvider
	TemplateName string
	MessageType  string
	DomainCode   string
}

func SMSFlow[T any](config SMSFlowConfig, getPhone func(T) string, getData func(T) map[string]interface{}) Flow[T] {
	return func(ctx *Context[T], next func() error) error {
		slog.Info("Flow: SMSSending - Before", "template", config.TemplateName)

		err := next()
		if err != nil {
			return err
		}

		toPhone := getPhone(ctx.Data)
		if toPhone == "" {
			slog.Warn("Flow: SMSSending - To phone is empty")
			return consts.VALIDATION_FAILED
		}

		template, found := config.AuthService.GetMessageTemplate(
			config.DomainCode,
			config.MessageType,
			config.TemplateName,
		)
		if !found {
			slog.Error("Flow: SMSSending - Template not found", "template", config.TemplateName)
			return consts.UNEXPECTED_FAILURE
		}

		templateData := getData(ctx.Data)

		flowContext := ctx.Context
		if flowContext == nil {
			flowContext = context.Background()
		}

		renderResult, renderErr := template.Render(flowContext, templateData)
		if renderErr != nil {
			slog.Error("Flow: SMSSending - Failed to render template", "error", renderErr)
			return renderErr
		}

		messageID, sendErr := config.SMSProvider.SendSMS(flowContext, toPhone, renderResult.GetBody())
		if sendErr != nil {
			slog.Error("Flow: SMSSending - Failed to send SMS", "error", sendErr, "to", toPhone)
			return sendErr
		}
		if messageID != nil {
			slog.Info("Flow: SMSSending - SMS sent with message ID", "messageID", *messageID, "to", toPhone)
		}

		slog.Info("Flow: SMSSending - SMS sent successfully", "to", toPhone, "template", config.TemplateName)
		return nil
	}
}
