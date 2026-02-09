package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type WebAuthnService struct {
	authService AuthService
	engine      WebAuthnEngine

	factorSvc    *MFAFactorService
	challengeSvc *MFAChallengeService
}

type WebAuthnBeginAuthenticationResult struct {
	WebAuthnAvailable bool            `json:"webauthn_available"`
	ChallengeID       string          `json:"challenge_id,omitempty"`
	RequestOptions    json.RawMessage `json:"request_options,omitempty"`
	Fallback          []string        `json:"fallback,omitempty"`
}

type WebAuthnBeginRegistrationResult struct {
	FactorID        string          `json:"factor_id"`
	ChallengeID     string          `json:"challenge_id"`
	CreationOptions json.RawMessage `json:"creation_options"`
	Fallback        []string        `json:"fallback,omitempty"`
}

type WebAuthnFinishRegistrationResult struct {
	Success bool `json:"success"`
}

type WebAuthnFinishAuthenticationResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    int64  `json:"expires_at"`
	ExpiresIn    int    `json:"expires_in"`
	SessionID    string `json:"session_id"`
	UserID       string `json:"user_id"`
}

type webAuthnSessionEnvelope struct {
	Purpose              string          `json:"purpose"`
	UserID               uint            `json:"user_id"`
	SessionData          json.RawMessage `json:"session_data"`
	AllowedCredentialIDs []string        `json:"allowed_credential_ids,omitempty"`
}

func NewWebAuthnService(authService AuthService, engine WebAuthnEngine) *WebAuthnService {
	return &WebAuthnService{
		authService:  authService,
		engine:       engine,
		factorSvc:    NewMFAFactorService(authService.GetDB()),
		challengeSvc: NewMFAChallengeService(authService.GetDB()),
	}
}

func (s *WebAuthnService) BeginAuthentication(ctx context.Context, rp WebAuthnRPConfig, identifier string, ipAddress string) (*WebAuthnBeginAuthenticationResult, error) {
	result := &WebAuthnBeginAuthenticationResult{
		WebAuthnAvailable: false,
		Fallback:          []string{"otp"},
	}

	userModel, err := s.authService.GetUserService().GetByIdentifier(ctx, identifier, s.authService.GetInstanceId())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return result, nil
		}
		return nil, err
	}

	factors, err := s.factorSvc.GetByUserIDAndType(ctx, userModel.ID, types.FactorTypeWebAuthn, s.authService.GetInstanceId())
	if err != nil {
		return nil, err
	}

	var allowIDs [][]byte
	for _, factor := range factors {
		if factor.Status != types.FactorStatusVerified || factor.WebAuthnCredential == nil {
			continue
		}
		credIDBytes, ok := extractStoredWebAuthnCredentialID(*factor.WebAuthnCredential)
		if !ok {
			continue
		}
		allowIDs = append(allowIDs, credIDBytes)
	}

	if len(allowIDs) == 0 {
		return result, nil
	}

	userHashID, err := GenerateUserHashID(userModel.ID)
	if err != nil {
		return nil, err
	}
	user := WebAuthnUser{
		ID:          []byte(userHashID),
		Name:        identifier,
		DisplayName: identifier,
	}

	requestOptions, sessionData, err := s.engine.BeginLogin(ctx, rp, user, allowIDs)
	if err != nil {
		return nil, err
	}

	allowedB64 := make([]string, 0, len(allowIDs))
	for _, id := range allowIDs {
		allowedB64 = append(allowedB64, base64.RawURLEncoding.EncodeToString(id))
	}
	envelopeBytes, err := json.Marshal(webAuthnSessionEnvelope{
		Purpose:              "authentication",
		UserID:               userModel.ID,
		SessionData:          sessionData,
		AllowedCredentialIDs: allowedB64,
	})
	if err != nil {
		return nil, err
	}
	envelope := json.RawMessage(envelopeBytes)

	challenge := &models.MFAChallenge{
		FactorID:            factors[0].ID,
		CreatedAt:           time.Now(),
		IPAddress:           ipAddress,
		WebAuthnSessionData: &envelope,
		InstanceId:          s.authService.GetInstanceId(),
	}
	if err := s.challengeSvc.Create(ctx, challenge); err != nil {
		return nil, err
	}

	challengeHashID, err := GenerateUserHashID(challenge.ID)
	if err != nil {
		return nil, err
	}

	result.WebAuthnAvailable = true
	result.ChallengeID = challengeHashID
	result.RequestOptions = requestOptions
	return result, nil
}

func (s *WebAuthnService) BeginRegistration(ctx context.Context, rp WebAuthnRPConfig, user *User, friendlyName string, ipAddress string) (*WebAuthnBeginRegistrationResult, error) {
	now := time.Now()
	factor := &models.MFAFactor{
		UserID:       user.ID,
		FriendlyName: &friendlyName,
		FactorType:   types.FactorTypeWebAuthn,
		Status:       types.FactorStatusUnverified,
		InstanceId:   s.authService.GetInstanceId(),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.factorSvc.Create(ctx, factor); err != nil {
		return nil, err
	}

	factorHashID, err := GenerateUserHashID(factor.ID)
	if err != nil {
		return nil, err
	}

	webauthnUser := WebAuthnUser{
		ID:          []byte(user.HashID),
		Name:        user.GetEmail(),
		DisplayName: user.GetEmail(),
	}
	if p := user.GetPhone(); p != "" {
		webauthnUser.Name = p
		webauthnUser.DisplayName = p
	}

	creationOptions, sessionData, err := s.engine.BeginRegistration(ctx, rp, webauthnUser, nil)
	if err != nil {
		return nil, err
	}

	envelopeBytes, err := json.Marshal(webAuthnSessionEnvelope{
		Purpose:     "registration",
		UserID:      user.ID,
		SessionData: sessionData,
	})
	if err != nil {
		return nil, err
	}
	envelope := json.RawMessage(envelopeBytes)

	challenge := &models.MFAChallenge{
		FactorID:            factor.ID,
		CreatedAt:           now,
		IPAddress:           ipAddress,
		WebAuthnSessionData: &envelope,
		InstanceId:          s.authService.GetInstanceId(),
	}
	if err := s.challengeSvc.Create(ctx, challenge); err != nil {
		return nil, err
	}

	challengeHashID, err := GenerateUserHashID(challenge.ID)
	if err != nil {
		return nil, err
	}

	return &WebAuthnBeginRegistrationResult{
		FactorID:        factorHashID,
		ChallengeID:     challengeHashID,
		CreationOptions: creationOptions,
		Fallback:        []string{"otp"},
	}, nil
}

func (s *WebAuthnService) FinishRegistration(ctx context.Context, rp WebAuthnRPConfig, challengeHashID string, attestationResponse json.RawMessage) (*WebAuthnFinishRegistrationResult, error) {
	challengeID, err := GetUserIDFromHashID(challengeHashID)
	if err != nil {
		return nil, err
	}

	challenge, err := s.challengeSvc.GetWithFactor(ctx, challengeID, s.authService.GetInstanceId())
	if err != nil {
		return nil, err
	}
	if challenge.WebAuthnSessionData == nil {
		return nil, errors.New("missing webauthn session data")
	}

	var envelope webAuthnSessionEnvelope
	if err := json.Unmarshal(*challenge.WebAuthnSessionData, &envelope); err != nil {
		return nil, err
	}
	if envelope.Purpose != "registration" {
		return nil, errors.New("invalid webauthn session purpose")
	}

	userHashID, err := GenerateUserHashID(envelope.UserID)
	if err != nil {
		return nil, err
	}
	userObj, err := s.authService.GetUserService().GetByHashID(ctx, userHashID)
	if err != nil {
		return nil, err
	}
	webauthnUser := WebAuthnUser{
		ID:          []byte(userObj.HashID),
		Name:        userObj.GetEmail(),
		DisplayName: userObj.GetEmail(),
	}
	if p := userObj.GetPhone(); p != "" {
		webauthnUser.Name = p
		webauthnUser.DisplayName = p
	}

	storedCredential, err := s.engine.FinishRegistration(ctx, rp, webauthnUser, envelope.SessionData, attestationResponse)
	if err != nil {
		return nil, err
	}

	challenge.Factor.WebAuthnCredential = &storedCredential
	challenge.Factor.Status = types.FactorStatusVerified
	if err := s.factorSvc.Update(ctx, challenge.Factor); err != nil {
		return nil, err
	}
	if err := s.challengeSvc.MarkAsVerified(ctx, challenge.ID, s.authService.GetInstanceId()); err != nil {
		return nil, err
	}

	return &WebAuthnFinishRegistrationResult{Success: true}, nil
}

func (s *WebAuthnService) FinishAuthentication(ctx context.Context, rp WebAuthnRPConfig, challengeHashID string, assertionResponse json.RawMessage, userAgent string, ipAddress string) (*WebAuthnFinishAuthenticationResult, error) {
	challengeID, err := GetUserIDFromHashID(challengeHashID)
	if err != nil {
		return nil, err
	}

	challenge, err := s.challengeSvc.GetWithFactor(ctx, challengeID, s.authService.GetInstanceId())
	if err != nil {
		return nil, err
	}
	if challenge.WebAuthnSessionData == nil {
		return nil, errors.New("missing webauthn session data")
	}

	var envelope webAuthnSessionEnvelope
	if err := json.Unmarshal(*challenge.WebAuthnSessionData, &envelope); err != nil {
		return nil, err
	}
	if envelope.Purpose != "authentication" {
		return nil, errors.New("invalid webauthn session purpose")
	}

	userHashID, err := GenerateUserHashID(envelope.UserID)
	if err != nil {
		return nil, err
	}
	userObj, err := s.authService.GetUserService().GetByHashID(ctx, userHashID)
	if err != nil {
		return nil, err
	}

	webauthnUser := WebAuthnUser{
		ID:          []byte(userObj.HashID),
		Name:        userObj.GetEmail(),
		DisplayName: userObj.GetEmail(),
	}
	if p := userObj.GetPhone(); p != "" {
		webauthnUser.Name = p
		webauthnUser.DisplayName = p
	}

	factors, err := s.factorSvc.GetByUserIDAndType(ctx, envelope.UserID, types.FactorTypeWebAuthn, s.authService.GetInstanceId())
	if err != nil {
		return nil, err
	}
	var storedCreds []json.RawMessage
	for _, factor := range factors {
		if factor.Status != types.FactorStatusVerified || factor.WebAuthnCredential == nil {
			continue
		}
		storedCreds = append(storedCreds, *factor.WebAuthnCredential)
	}
	if len(storedCreds) == 0 {
		return nil, errors.New("no webauthn credentials")
	}

	updatedCred, err := s.engine.FinishLogin(ctx, rp, webauthnUser, envelope.SessionData, assertionResponse, storedCreds)
	if err != nil {
		return nil, err
	}

	updatedCredID, ok := extractStoredWebAuthnCredentialID(updatedCred)
	if !ok {
		return nil, errors.New("invalid stored credential")
	}

	var updatedFactor *models.MFAFactor
	for i := range factors {
		if factors[i].WebAuthnCredential == nil {
			continue
		}
		id, ok := extractStoredWebAuthnCredentialID(*factors[i].WebAuthnCredential)
		if ok && string(id) == string(updatedCredID) {
			updatedFactor = &factors[i]
			break
		}
	}
	if updatedFactor != nil {
		updatedFactor.WebAuthnCredential = &updatedCred
		if err := s.factorSvc.Update(ctx, updatedFactor); err != nil {
			return nil, err
		}
	}

	if err := s.challengeSvc.MarkAsVerified(ctx, challenge.ID, s.authService.GetInstanceId()); err != nil {
		return nil, err
	}

	session, accessToken, refreshToken, expiresAt, err := s.authService.CreateSession(ctx, userObj, types.AALLevel1, []string{"webauthn"}, userAgent, ipAddress)
	if err != nil {
		return nil, err
	}

	expiresIn := int(expiresAt - time.Now().Unix())
	if expiresIn < 0 {
		expiresIn = 0
	}

	return &WebAuthnFinishAuthenticationResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
		ExpiresIn:    expiresIn,
		SessionID:    session.HashID,
		UserID:       userObj.HashID,
	}, nil
}

func extractStoredWebAuthnCredentialID(raw json.RawMessage) ([]byte, bool) {
	var payload struct {
		CredentialID string `json:"credential_id"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, false
	}
	if payload.CredentialID == "" {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload.CredentialID)
	if err != nil {
		return nil, false
	}
	return b, true
}
