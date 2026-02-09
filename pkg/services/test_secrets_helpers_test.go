package services_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/thecybersailor/slauth/pkg/types"
)

func newTestSecretsProvider(t *testing.T) *staticSecretsProvider {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	kid := "test-key"
	return &staticSecretsProvider{
		secrets: &types.InstanceSecrets{
			PrimaryKeyId: kid,
			Keys: map[string]*types.SigningKey{
				kid: {
					Kid:        kid,
					Algorithm:  types.SignAlgES256,
					PrivateKey: string(privatePEM),
					PublicKey:  string(publicPEM),
				},
			},
			AppSecret: "test-app-secret",
		},
	}
}
