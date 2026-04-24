package reauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

const (
	ChannelEmail = "email"
	ChannelSMS   = "sms"
)

type ChallengeResult struct {
	MessageID   string
	SessionCode string
	Channel     string
	ExpiresAt   int64
}

type VerifyResult struct {
	Channel   string
	ExpiresAt time.Time
}

func ResolveChannel(user *services.User, requestedChannel string) (string, string, error) {
	channel := strings.ToLower(strings.TrimSpace(requestedChannel))

	switch channel {
	case "":
		if email := user.GetEmail(); email != "" {
			return ChannelEmail, email, nil
		}
		if phone := user.GetPhone(); phone != "" {
			return ChannelSMS, phone, nil
		}
	case ChannelEmail:
		if email := user.GetEmail(); email != "" {
			return ChannelEmail, email, nil
		}
	case ChannelSMS:
		if phone := user.GetPhone(); phone != "" {
			return ChannelSMS, phone, nil
		}
	}

	return "", "", consts.VALIDATION_FAILED
}

func SendChallenge(ctx context.Context, authService services.AuthService, user *services.User, requestedChannel string) (*ChallengeResult, error) {
	channel, target, err := ResolveChannel(user, requestedChannel)
	if err != nil {
		return nil, err
	}

	authServiceImpl, ok := authService.(*services.AuthServiceImpl)
	if !ok {
		return nil, consts.UNEXPECTED_FAILURE
	}

	otpService := authServiceImpl.GetOTPService()
	code, err := otpService.GenerateCode(nil)
	if err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}

	var email string
	var phone string
	if channel == ChannelEmail {
		email = target
	} else {
		phone = target
	}

	sessionCode, err := otpService.StoreOTP(
		ctx,
		email,
		phone,
		code,
		types.OneTimeTokenTypeReauthentication,
		authService.GetInstanceId(),
		authServiceImpl.GetDB(),
	)
	if err != nil {
		return nil, err
	}

	var messageID *string
	if channel == ChannelEmail {
		subject := "Reauthentication Code"
		body := fmt.Sprintf("Your verification code is: %s", code)
		messageID, err = authService.GetEmailProvider().SendEmail(ctx, target, subject, body)
	} else {
		body := fmt.Sprintf("Your verification code is: %s", code)
		messageID, err = authService.GetSMSProvider().SendSMS(ctx, target, body)
	}
	if err != nil {
		return nil, err
	}

	result := &ChallengeResult{
		SessionCode: sessionCode,
		Channel:     channel,
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	if messageID != nil {
		result.MessageID = *messageID
	}
	return result, nil
}

func VerifyChallenge(
	ctx context.Context,
	authService services.AuthService,
	user *services.User,
	sessionID uint,
	requestedChannel string,
	token string,
	sessionCode string,
) (*VerifyResult, error) {
	channel, target, err := ResolveChannel(user, requestedChannel)
	if err != nil {
		return nil, err
	}

	authServiceImpl, ok := authService.(*services.AuthServiceImpl)
	if !ok {
		return nil, consts.UNEXPECTED_FAILURE
	}

	otpService := authServiceImpl.GetOTPService()
	var email string
	var phone string
	if channel == ChannelEmail {
		email = target
	} else {
		phone = target
	}

	valid, err := otpService.VerifyOTP(
		ctx,
		email,
		phone,
		token,
		sessionCode,
		types.OneTimeTokenTypeReauthentication,
		authService.GetInstanceId(),
		authServiceImpl.GetDB(),
	)
	if err != nil || !valid {
		return nil, consts.REAUTHENTICATION_NOT_VALID
	}

	aalTimeout := authService.GetConfig().SecurityConfig.AALPolicy.AALTimeout
	expiresAt := time.Now().Add(aalTimeout)

	sessionService := services.NewSessionService(authService.GetDB())
	if err := sessionService.UpdateAALWithExpiry(ctx, sessionID, authService.GetInstanceId(), types.AALLevel2, &expiresAt); err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}

	return &VerifyResult{
		Channel:   channel,
		ExpiresAt: expiresAt,
	}, nil
}
