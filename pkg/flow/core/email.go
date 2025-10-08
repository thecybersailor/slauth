package core

import (
	"context"
	"log/slog"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type EmailFlowConfig struct {
	AuthService   services.AuthService
	EmailProvider types.EmailProvider
	TemplateName  string
	MessageType   string
	InstanceId    string
}

func EmailFlow[T any](config EmailFlowConfig, getEmail func(T) string, getData func(T) map[string]interface{}) Flow[T] {
	return func(ctx *Context[T], next func() error) error {
		slog.Info("Flow: EmailSending - Before", "template", config.TemplateName)

		err := next()
		if err != nil {
			return err
		}

		toEmail := getEmail(ctx.Data)
		if toEmail == "" {
			slog.Warn("Flow: EmailSending - To email is empty")
			return consts.VALIDATION_FAILED
		}

		template, found := config.AuthService.GetMessageTemplate(
			config.InstanceId,
			config.MessageType,
			config.TemplateName,
		)
		if !found {
			slog.Error("Flow: EmailSending - Template not found", "template", config.TemplateName)
			return consts.UNEXPECTED_FAILURE
		}

		templateData := getData(ctx.Data)

		flowContext := ctx.Context
		if flowContext == nil {
			flowContext = context.Background()
		}

		renderResult, renderErr := template.Render(flowContext, templateData)
		if renderErr != nil {
			slog.Error("Flow: EmailSending - Failed to render template", "error", renderErr)
			return renderErr
		}

		subject := ""
		if renderResult.GetSubject() != nil {
			subject = *renderResult.GetSubject()
		}
		messageID, sendErr := config.EmailProvider.SendEmail(flowContext, toEmail, subject, renderResult.GetBody())
		if sendErr != nil {
			slog.Error("Flow: EmailSending - Failed to send email", "error", sendErr, "to", toEmail)
			return sendErr
		}
		if messageID != nil {
			slog.Info("Flow: EmailSending - Email sent with message ID", "messageID", *messageID, "to", toEmail)
		}

		slog.Info("Flow: EmailSending - Email sent successfully", "to", toEmail, "template", config.TemplateName)
		return nil
	}
}
