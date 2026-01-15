package controller

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/types"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type (RSA/EC)
	Use string `json:"use"` // Public Key Use (sig)
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm

	// ECDSA fields
	Crv string `json:"crv,omitempty"` // Curve (P-256)
	X   string `json:"x,omitempty"`   // X coordinate
	Y   string `json:"y,omitempty"`   // Y coordinate

	// RSA fields
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// publicKeyToJWK converts PEM public key to JWK format
func publicKeyToJWK(publicKeyPEM string, algorithm types.SignAlgorithm, kid string) (JWK, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return JWK{}, http.ErrNotSupported
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return JWK{}, err
	}

	jwk := JWK{
		Use: "sig",
		Kid: kid,
		Alg: string(algorithm),
	}

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.Crv = "P-256"
		jwk.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())

	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	default:
		return JWK{}, http.ErrNotSupported
	}

	return jwk, nil
}

// HandleJWKS handles GET /.well-known/jwks.json endpoint
func HandleJWKS(secretsProvider types.InstanceSecretsProvider, instanceId string) gin.HandlerFunc {
	return func(c *gin.Context) {
		secrets, err := secretsProvider.GetSecrets(instanceId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load keys"})
			return
		}

		jwks := &JWKS{Keys: []JWK{}}

		for kid, key := range secrets.Keys {
			jwk, err := publicKeyToJWK(key.PublicKey, key.Algorithm, kid)
			if err != nil {
				continue // Skip invalid keys
			}
			jwks.Keys = append(jwks.Keys, jwk)
		}

		c.JSON(http.StatusOK, jwks)
	}
}
