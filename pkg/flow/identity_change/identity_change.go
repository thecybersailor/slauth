package identity_change

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type Kind string

const (
	KindEmail Kind = "email_change"
	KindPhone Kind = "phone_change"
)

type Stage string

const (
	StageVerifyNew     Stage = "verify_new"
	StageVerifyCurrent Stage = "verify_current"
	StageCompleted     Stage = "completed"
)

const authenticationMethod = "identity_change"

type stateFlags struct {
	RequireCurrentValueConfirmation bool `json:"require_current_value_confirmation"`
	NewValueVerified                bool `json:"new_value_verified"`
	CurrentValueVerified            bool `json:"current_value_verified"`
}

type State struct {
	Kind         Kind
	CurrentValue string
	NewValue     string
	Stage        Stage
	Flags        stateFlags
}

type StartResult struct {
	FlowStateID uint
	SessionCode string
	Stage       Stage
	Channel     string
}

type VerifyResult struct {
	FlowStateID uint
	Completed   bool
	Stage       Stage
	SessionCode string
	Channel     string
}

func Start(
	ctx context.Context,
	authService services.AuthService,
	user *services.User,
	kind Kind,
	newValue string,
	currentAAL types.AALLevel,
) (*StartResult, error) {
	if user == nil {
		return nil, consts.USER_NOT_FOUND
	}

	cfg, err := resolveConfig(authService, kind)
	if err != nil {
		return nil, err
	}
	if !aalSatisfies(currentAAL, cfg.RequiredAAL) {
		return nil, consts.INSUFFICIENT_AAL
	}

	normalizedNewValue, err := validateAndNormalize(authService, kind, newValue)
	if err != nil {
		return nil, err
	}
	currentValue := currentValueForKind(user, kind)
	if currentValue == "" {
		return nil, consts.VALIDATION_FAILED
	}
	if sameIdentityValue(kind, currentValue, normalizedNewValue) {
		return nil, consts.VALIDATION_FAILED
	}
	if err := ensureNoConflict(ctx, authService, user, kind, normalizedNewValue); err != nil {
		return nil, err
	}

	flowState := &models.FlowState{
		UserID:               user.ID,
		AuthCode:             string(kind),
		CodeChallengeMethod:  string(StageVerifyNew),
		CodeChallenge:        currentValue,
		CodeVerifier:         normalizedNewValue,
		ProviderType:         string(kind),
		AuthenticationMethod: authenticationMethod,
		InstanceId:           authService.GetInstanceId(),
	}

	flags := stateFlags{
		RequireCurrentValueConfirmation: cfg.RequireCurrentValueConfirmation,
	}
	if err := writeFlags(flowState, flags); err != nil {
		return nil, consts.UNEXPECTED_FAILURE
	}
	if err := authService.CreateFlowState(ctx, flowState); err != nil {
		return nil, err
	}

	sessionCode, channel, err := sendChallenge(ctx, authService, kind, StageVerifyNew, normalizedNewValue)
	if err != nil {
		return nil, err
	}

	return &StartResult{
		FlowStateID: flowState.ID,
		SessionCode: sessionCode,
		Stage:       StageVerifyNew,
		Channel:     channel,
	}, nil
}

func Verify(
	ctx context.Context,
	authService services.AuthService,
	user *services.User,
	flowStateID uint,
	kind Kind,
	token string,
	sessionCode string,
) (*VerifyResult, error) {
	if user == nil {
		return nil, consts.USER_NOT_FOUND
	}

	flowState, err := authService.GetFlowStateByID(ctx, flowStateID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, consts.FLOW_STATE_NOT_FOUND
		}
		return nil, err
	}

	state, err := DecodeFlowState(flowState)
	if err != nil {
		return nil, err
	}
	if flowState.UserID != user.ID || state.Kind != kind || flowState.InstanceId != authService.GetInstanceId() || flowState.AuthenticationMethod != authenticationMethod {
		return nil, consts.FLOW_STATE_NOT_FOUND
	}

	stage := state.Stage
	targetValue := state.NewValue
	if stage == StageVerifyCurrent {
		targetValue = state.CurrentValue
	}

	if err := verifyChallenge(ctx, authService, kind, stage, targetValue, token, sessionCode); err != nil {
		return nil, err
	}

	switch stage {
	case StageVerifyNew:
		state.Flags.NewValueVerified = true
		if state.Flags.RequireCurrentValueConfirmation {
			state.Stage = StageVerifyCurrent
			if err := applyState(flowState, state); err != nil {
				return nil, err
			}
			if err := authService.UpdateFlowState(ctx, flowState); err != nil {
				return nil, err
			}

			nextSessionCode, channel, err := sendChallenge(ctx, authService, kind, StageVerifyCurrent, state.CurrentValue)
			if err != nil {
				return nil, err
			}

			return &VerifyResult{
				FlowStateID: flowState.ID,
				Completed:   false,
				Stage:       StageVerifyCurrent,
				SessionCode: nextSessionCode,
				Channel:     channel,
			}, nil
		}
	case StageVerifyCurrent:
		state.Flags.CurrentValueVerified = true
	default:
		return nil, consts.VALIDATION_FAILED
	}

	if err := persistIdentityChange(ctx, user, state.Kind, state.NewValue); err != nil {
		return nil, err
	}
	state.Stage = StageCompleted
	if err := applyState(flowState, state); err != nil {
		return nil, err
	}
	if err := authService.UpdateFlowState(ctx, flowState); err != nil {
		return nil, err
	}

	return &VerifyResult{
		FlowStateID: flowState.ID,
		Completed:   true,
		Stage:       StageCompleted,
		Channel:     challengeChannel(kind),
	}, nil
}

func DecodeFlowState(flowState *models.FlowState) (*State, error) {
	if flowState == nil || flowState.AuthenticationMethod != authenticationMethod {
		return nil, consts.FLOW_STATE_NOT_FOUND
	}

	flags, err := readFlags(flowState)
	if err != nil {
		return nil, err
	}

	return &State{
		Kind:         Kind(flowState.ProviderType),
		CurrentValue: flowState.CodeChallenge,
		NewValue:     flowState.CodeVerifier,
		Stage:        Stage(flowState.CodeChallengeMethod),
		Flags:        flags,
	}, nil
}

func applyState(flowState *models.FlowState, state *State) error {
	flowState.ProviderType = string(state.Kind)
	flowState.CodeChallenge = state.CurrentValue
	flowState.CodeVerifier = state.NewValue
	flowState.CodeChallengeMethod = string(state.Stage)
	return writeFlags(flowState, state.Flags)
}

func writeFlags(flowState *models.FlowState, flags stateFlags) error {
	bin, err := json.Marshal(flags)
	if err != nil {
		return err
	}
	flowState.RedirectURI = string(bin)
	return nil
}

func readFlags(flowState *models.FlowState) (stateFlags, error) {
	if strings.TrimSpace(flowState.RedirectURI) == "" {
		return stateFlags{}, nil
	}

	var flags stateFlags
	if err := json.Unmarshal([]byte(flowState.RedirectURI), &flags); err != nil {
		return stateFlags{}, consts.UNEXPECTED_FAILURE
	}
	return flags, nil
}

func resolveConfig(authService services.AuthService, kind Kind) (config.IdentityChangeConfig, error) {
	cfg := authService.GetConfig()
	if cfg == nil || cfg.SecurityConfig == nil {
		return config.IdentityChangeConfig{}, consts.UNEXPECTED_FAILURE
	}

	switch kind {
	case KindEmail:
		return cfg.SecurityConfig.EmailChangeConfig, nil
	case KindPhone:
		return cfg.SecurityConfig.PhoneChangeConfig, nil
	default:
		return config.IdentityChangeConfig{}, consts.VALIDATION_FAILED
	}
}

func validateAndNormalize(authService services.AuthService, kind Kind, value string) (string, error) {
	validator := services.NewValidatorService()
	trimmed := strings.TrimSpace(value)

	switch kind {
	case KindEmail:
		if err := validator.ValidateEmail(trimmed); err != nil {
			return "", err
		}
		return strings.ToLower(trimmed), nil
	case KindPhone:
		if err := validator.ValidatePhone(trimmed); err != nil {
			return "", err
		}
		return trimmed, nil
	default:
		return "", consts.VALIDATION_FAILED
	}
}

func currentValueForKind(user *services.User, kind Kind) string {
	switch kind {
	case KindEmail:
		return user.GetEmail()
	case KindPhone:
		return user.GetPhone()
	default:
		return ""
	}
}

func sameIdentityValue(kind Kind, currentValue, newValue string) bool {
	if kind == KindEmail {
		return strings.EqualFold(strings.TrimSpace(currentValue), strings.TrimSpace(newValue))
	}
	return strings.TrimSpace(currentValue) == strings.TrimSpace(newValue)
}

func ensureNoConflict(ctx context.Context, authService services.AuthService, user *services.User, kind Kind, newValue string) error {
	switch kind {
	case KindEmail:
		existing, err := authService.GetUserService().GetByEmail(ctx, newValue)
		if err == nil && existing != nil && existing.ID != user.ID {
			return consts.EMAIL_EXISTS
		}
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
	case KindPhone:
		existing, err := authService.GetUserService().GetByPhone(ctx, newValue, authService.GetInstanceId())
		if err == nil && existing != nil && existing.ID != user.ID {
			return consts.PHONE_EXISTS
		}
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
	default:
		return consts.VALIDATION_FAILED
	}
	return nil
}

func sendChallenge(ctx context.Context, authService services.AuthService, kind Kind, stage Stage, targetValue string) (string, string, error) {
	authServiceImpl, ok := authService.(*services.AuthServiceImpl)
	if !ok {
		return "", "", consts.UNEXPECTED_FAILURE
	}

	otpService := authServiceImpl.GetOTPService()
	code, err := otpService.GenerateCode(nil)
	if err != nil {
		return "", "", consts.UNEXPECTED_FAILURE
	}

	email := ""
	phone := ""
	if kind == KindEmail {
		email = targetValue
	} else {
		phone = targetValue
	}

	sessionCode, err := otpService.StoreOTP(
		ctx,
		email,
		phone,
		code,
		tokenTypeFor(kind, stage),
		authService.GetInstanceId(),
		authServiceImpl.GetDB(),
	)
	if err != nil {
		return "", "", err
	}

	message := fmt.Sprintf("Your verification code is: %s", code)
	if kind == KindEmail {
		subject := "Identity Change Verification"
		if stage == StageVerifyCurrent {
			subject = "Current Address Verification"
		}
		if _, err := authService.GetEmailProvider().SendEmail(ctx, targetValue, subject, message); err != nil {
			return "", "", err
		}
		return sessionCode, "email", nil
	}

	if _, err := authService.GetSMSProvider().SendSMS(ctx, targetValue, message); err != nil {
		return "", "", err
	}
	return sessionCode, "sms", nil
}

func verifyChallenge(ctx context.Context, authService services.AuthService, kind Kind, stage Stage, targetValue, token, sessionCode string) error {
	authServiceImpl, ok := authService.(*services.AuthServiceImpl)
	if !ok {
		return consts.UNEXPECTED_FAILURE
	}

	otpService := authServiceImpl.GetOTPService()
	email := ""
	phone := ""
	if kind == KindEmail {
		email = targetValue
	} else {
		phone = targetValue
	}

	valid, err := otpService.VerifyOTP(
		ctx,
		email,
		phone,
		token,
		sessionCode,
		tokenTypeFor(kind, stage),
		authService.GetInstanceId(),
		authServiceImpl.GetDB(),
	)
	if err != nil || !valid {
		return consts.VALIDATION_FAILED
	}
	return nil
}

func persistIdentityChange(ctx context.Context, user *services.User, kind Kind, newValue string) error {
	switch kind {
	case KindEmail:
		return user.UpdateEmail(ctx, newValue)
	case KindPhone:
		return user.UpdatePhone(ctx, newValue)
	default:
		return consts.VALIDATION_FAILED
	}
}

func tokenTypeFor(kind Kind, stage Stage) types.OneTimeTokenType {
	switch kind {
	case KindEmail:
		if stage == StageVerifyCurrent {
			return types.OneTimeTokenTypeEmailChangeCurrent
		}
		return types.OneTimeTokenTypeEmailChangeNew
	case KindPhone:
		if stage == StageVerifyCurrent {
			return types.OneTimeTokenTypePhoneChangeCurrent
		}
		return types.OneTimeTokenTypePhoneChange
	default:
		return types.OneTimeTokenTypeConfirmation
	}
}

func challengeChannel(kind Kind) string {
	if kind == KindEmail {
		return "email"
	}
	return "sms"
}

func aalSatisfies(current, required types.AALLevel) bool {
	return aalRank(current) >= aalRank(required)
}

func aalRank(level types.AALLevel) int {
	switch level {
	case types.AALLevel3:
		return 3
	case types.AALLevel2:
		return 2
	default:
		return 1
	}
}
