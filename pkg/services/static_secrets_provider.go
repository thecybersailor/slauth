package services

import (
	"github.com/thecybersailor/slauth/pkg/types"
)

// StaticSecretsProvider provides hardcoded secrets for development/testing
type StaticSecretsProvider struct {
	secrets *types.InstanceSecrets
}

// NewStaticSecretsProvider creates a provider with hardcoded secrets
func NewStaticSecretsProvider(secrets *types.InstanceSecrets) *StaticSecretsProvider {
	return &StaticSecretsProvider{
		secrets: secrets,
	}
}

// GetSecrets returns the hardcoded secrets
func (p *StaticSecretsProvider) GetSecrets(instanceId string) (*types.InstanceSecrets, error) {
	return p.secrets, nil
}
