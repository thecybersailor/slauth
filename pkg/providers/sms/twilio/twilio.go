package twilio

import (
	"context"
	"fmt"

	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

type SMSTwilioSender struct {
	client *twilio.RestClient
}

func NewTwilioProvider(accountSid, authToken string) *SMSTwilioSender {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})
	return &SMSTwilioSender{client: client}
}

func (p *SMSTwilioSender) SendSMS(ctx context.Context, phone string, message string) (messageID *string, err error) {
	params := &twilioApi.CreateMessageParams{}
	params.SetTo(phone)
	params.SetBody(message)

	resp, err := p.client.Api.CreateMessage(params)
	if err != nil {
		return nil, fmt.Errorf("failed to send SMS via Twilio: %w", err)
	}

	return resp.Sid, nil
}
