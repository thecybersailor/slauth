package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/thecybersailor/slauth/pkg/types"
)

type AWSSMSProvider struct {
	snsClient *sns.Client
}

func NewAWSSMSProvider(awsConfig aws.Config) types.SMSProvider {
	snsClient := sns.NewFromConfig(awsConfig)
	return &AWSSMSProvider{snsClient: snsClient}
}

func (a *AWSSMSProvider) SendSMS(ctx context.Context, phone string, message string) (messageID *string, err error) {
	resp, err := a.snsClient.Publish(ctx, &sns.PublishInput{
		PhoneNumber: aws.String(phone),
		Message:     aws.String(message),
	})
	if err != nil {
		return nil, err
	}
	return resp.MessageId, nil
}
