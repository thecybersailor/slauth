package adapters

import (
	"context"

	"github.com/flaboy/aira-core/pkg/mailer"
	"github.com/thecybersailor/slauth/pkg/types"
)

type MailerAdapter struct {
	mailer *mailer.Mailer
}

func NewMailerAdapter(m *mailer.Mailer) types.EmailProvider {
	return &MailerAdapter{mailer: m}
}

func (m *MailerAdapter) SendEmail(ctx context.Context, to string, subject string, body string) (*string, error) {
	err := m.mailer.SendMail(ctx, to, subject, body)
	if err != nil {
		return nil, err
	}
	return nil, nil
}
