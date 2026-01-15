package tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

type TestHelper struct {
	DB            *gorm.DB
	Router        *gin.Engine
	TestInstance  string
	EmailProvider *MockEmailProvider
	SMSProvider   *MockSMSProvider
}

func NewTestHelper(db *gorm.DB, router *gin.Engine, instance string, emailProvider *MockEmailProvider, smsProvider *MockSMSProvider) *TestHelper {
	return &TestHelper{
		DB:            db,
		Router:        router,
		TestInstance:  instance,
		EmailProvider: emailProvider,
		SMSProvider:   smsProvider,
	}
}

func (h *TestHelper) GetMockEmailProvider() *MockEmailProvider {
	return h.EmailProvider
}

func (h *TestHelper) GetMockSMSProvider() *MockSMSProvider {
	return h.SMSProvider
}

type PinResponse struct {
	pin.Response
	ResponseRecorder *httptest.ResponseRecorder
}

func (pr *PinResponse) Print() {
	bin, _ := json.MarshalIndent(pr.Response, "", "  ")
	fmt.Println(string(bin))
}

func (h *TestHelper) MakePOSTRequest(t *testing.T, path string, body S) *PinResponse {
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req, err := http.NewRequest("POST", path, bytes.NewBuffer(jsonBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	err = json.Unmarshal(w.Body.Bytes(), &rsp.Response)
	assert.NoError(t, err)

	return rsp
}

func (h *TestHelper) MakeGETRequest(t *testing.T, path string) *PinResponse {
	req, err := http.NewRequest("GET", path, nil)
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	// Try to parse as pin.Response, ignore error if failed (for 401 and other error responses)
	json.Unmarshal(w.Body.Bytes(), &rsp.Response)

	return rsp
}

func (h *TestHelper) MakeGETRequestWithHeaders(t *testing.T, path string) *PinResponse {
	req, err := http.NewRequest("GET", path, nil)
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	err = json.Unmarshal(w.Body.Bytes(), &rsp.Response)
	assert.NoError(t, err)

	return rsp
}

// MakeGETRequestWithAuth creates GET request with authentication header
func (h *TestHelper) MakeGETRequestWithAuth(t *testing.T, path string, accessToken string) *PinResponse {
	req, err := http.NewRequest("GET", path, nil)
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	// Try to parse as pin.Response, ignore error if failed (for 401 and other error responses)
	json.Unmarshal(w.Body.Bytes(), &rsp.Response)

	return rsp
}

// MakeGETRequestWithAuthRaw creates GET request with authentication header, returns raw response
func (h *TestHelper) MakeGETRequestWithAuthRaw(t *testing.T, path string, accessToken string) *httptest.ResponseRecorder {
	req, err := http.NewRequest("GET", path, nil)
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	return w
}

// MakePOSTRequestWithIP creates POST request with custom IP address
func (h *TestHelper) MakePOSTRequestWithIP(t *testing.T, path string, body S, clientIP string) *PinResponse {
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req, err := http.NewRequest("POST", path, bytes.NewBuffer(jsonBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	// Set custom IP address
	req.RemoteAddr = clientIP + ":12345"

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	err = json.Unmarshal(w.Body.Bytes(), &rsp.Response)
	assert.NoError(t, err)

	return rsp
}

// MakePOSTRequestWithHeaders creates POST request with custom HTTP headers
func (h *TestHelper) MakePOSTRequestWithHeaders(t *testing.T, path string, body S, headers map[string]string) *PinResponse {
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req, err := http.NewRequest("POST", path, bytes.NewBuffer(jsonBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	err = json.Unmarshal(w.Body.Bytes(), &rsp.Response)
	assert.NoError(t, err)

	return rsp
}

func (h *TestHelper) HasError(t *testing.T, rsp *PinResponse, errorField string, msg string) {
	if !assert.NotNil(t, rsp.Response.Error, msg+": Response should be an error") {
		return
	}
	assert.Contains(t, rsp.Response.Error.Key, errorField, msg+": Error should contain: %s", errorField)
}

func (h *TestHelper) IsError(t *testing.T, rsp *PinResponse, err error) {
	// Check that response has an error
	if !assert.NotNil(t, rsp.Response.Error, "Response should have an error") {
		return
	}

	// Extract expected error code
	var expectedCode string
	if ue, ok := err.(interface{ Code() string }); ok {
		expectedCode = ue.Code()
	} else {
		expectedCode = err.Error()
	}

	// Compare error code
	assert.Equal(t, expectedCode, rsp.Response.Error.Key, "Error code should match")
}

func (h *TestHelper) MatchObject(t *testing.T, rsp *PinResponse, target S, msg string) {
	assert.NotNil(t, rsp.Response.Data, msg+": Response should have data")

	var responseData map[string]any
	responseBytes, _ := json.Marshal(rsp.Response.Data)
	json.Unmarshal(responseBytes, &responseData)

	matchObjectRecursive(t, responseData, target, "", msg)
}

func matchObjectRecursive(t *testing.T, actual map[string]any, expected S, path string, msg string) {
	for key, expectedValue := range expected {
		currentPath := key
		if path != "" {
			currentPath = path + "." + key
		}

		// Check if field exists in actual data
		actualValue, exists := actual[key]
		assert.True(t, exists, msg+": Field %s should exist", currentPath)

		// Handle nested objects
		if expectedMap, ok := expectedValue.(S); ok {
			if actualMap, ok := actualValue.(map[string]any); ok {
				matchObjectRecursive(t, actualMap, expectedMap, currentPath, msg)
			} else {
				assert.Fail(t, msg+": Field %s should be an object", currentPath)
			}
		} else if expectedMap, ok := expectedValue.(map[string]any); ok {
			if actualMap, ok := actualValue.(map[string]any); ok {
				matchObjectRecursive(t, actualMap, expectedMap, currentPath, msg)
			} else {
				assert.Fail(t, msg+": Field %s should be an object", currentPath)
			}
		} else if expectedSlice, ok := expectedValue.([]any); ok {
			// Handle arrays
			if actualSlice, ok := actualValue.([]any); ok {
				matchArrayRecursive(t, actualSlice, expectedSlice, currentPath, msg)
			} else {
				assert.Fail(t, msg+": Field %s should be an array", currentPath)
			}
		} else {
			// Compare leaf node values
			assert.Equal(t, expectedValue, actualValue, msg+": Field %s should match", currentPath)
		}
	}
}

func matchArrayRecursive(t *testing.T, actual []any, expected []any, path string, msg string) {
	assert.Equal(t, len(expected), len(actual), msg+": Array %s should have same length", path)

	for i, expectedItem := range expected {
		currentPath := fmt.Sprintf("%s[%d]", path, i)

		// Handle objects in array (supports S type and map[string]any)
		if expectedMap, ok := expectedItem.(S); ok {
			// Convert S to map[string]any
			expectedMapAny := make(map[string]any)
			for k, v := range expectedMap {
				expectedMapAny[k] = v
			}
			if actualMap, ok := actual[i].(map[string]any); ok {
				matchObjectRecursive(t, actualMap, expectedMapAny, currentPath, msg)
			} else {
				assert.Fail(t, msg+": Array item %s should be an object", currentPath)
			}
		} else if expectedMap, ok := expectedItem.(map[string]any); ok {
			if actualMap, ok := actual[i].(map[string]any); ok {
				matchObjectRecursive(t, actualMap, expectedMap, currentPath, msg)
			} else {
				assert.Fail(t, msg+": Array item %s should be an object", currentPath)
			}
		} else if expectedSlice, ok := expectedItem.([]any); ok {
			// Handle nested arrays
			if actualSlice, ok := actual[i].([]any); ok {
				matchArrayRecursive(t, actualSlice, expectedSlice, currentPath, msg)
			} else {
				assert.Fail(t, msg+": Array item %s should be an array", currentPath)
			}
		} else {
			// Compare primitive type values in array
			assert.Equal(t, expectedItem, actual[i], msg+": Array item %s should match", currentPath)
		}
	}
}

// MakePOSTFormRequest creates form POST request (for SAML callback, etc.)
func (h *TestHelper) MakePOSTFormRequest(t *testing.T, path string, formData map[string]string) *PinResponse {
	// Build form data
	formValues := make([]string, 0, len(formData))
	for key, value := range formData {
		formValues = append(formValues, fmt.Sprintf("%s=%s", key, value))
	}
	formBody := strings.Join(formValues, "&")

	req, err := http.NewRequest("POST", path, strings.NewReader(formBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	h.Router.ServeHTTP(recorder, req)

	var response pin.Response
	err = json.Unmarshal(recorder.Body.Bytes(), &response)
	if err != nil {
		// If not JSON response, create a basic response structure
		response = pin.Response{
			Data: recorder.Body.String(),
		}
	}

	return &PinResponse{
		Response:         response,
		ResponseRecorder: recorder,
	}
}

// MakePUTRequest creates PUT request
func (h *TestHelper) MakePUTRequest(t *testing.T, path string, body S, headers map[string]string) *PinResponse {
	var jsonBody []byte
	var err error

	if body != nil {
		jsonBody, err = json.Marshal(body)
		assert.NoError(t, err)
	}

	req, err := http.NewRequest("PUT", path, bytes.NewBuffer(jsonBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	// Try to parse as pin.Response, ignore error if failed
	json.Unmarshal(w.Body.Bytes(), &rsp.Response)

	return rsp
}

// MakeDELETERequest creates DELETE request
func (h *TestHelper) MakeDELETERequest(t *testing.T, path string, body S, headers map[string]string) *PinResponse {
	var jsonBody []byte
	var err error

	if body != nil {
		jsonBody, err = json.Marshal(body)
		assert.NoError(t, err)
	}

	req, err := http.NewRequest("DELETE", path, bytes.NewBuffer(jsonBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)

	rsp := &PinResponse{
		ResponseRecorder: w,
	}

	// Try to parse as pin.Response, ignore error if failed
	json.Unmarshal(w.Body.Bytes(), &rsp.Response)

	return rsp
}

// JWTClaims represents the JWT claims structure (copy for testing)
type JWTClaims struct {
	jwt.RegisteredClaims
	UserID     string         `json:"user_id"`
	InstanceId string         `json:"instance_id"`
	Email      string         `json:"email,omitempty"`
	Phone      string         `json:"phone,omitempty"`
	Role       string         `json:"role,omitempty"`
	AAL        types.AALLevel `json:"aal"`
	AMR        []string       `json:"amr"` // Authentication Method Reference
	SessionID  uint           `json:"session_id"`
	UserMeta   map[string]any `json:"user_metadata,omitempty"`
	AppMeta    map[string]any `json:"app_metadata,omitempty"`
}

// JWKPublicKey represents parsed public key from JWKS endpoint
type JWKPublicKey struct {
	Kid       string
	Algorithm types.SignAlgorithm
	PublicKey interface{} // *ecdsa.PublicKey or *rsa.PublicKey
}

// FetchJWKSKeys fetches and parses public keys from JWKS endpoint
func (h *TestHelper) FetchJWKSKeys(t *testing.T, jwksURL string) map[string]*JWKPublicKey {
	response := h.MakeGETRequest(t, jwksURL)
	assert.Equal(t, http.StatusOK, response.ResponseRecorder.Code, "JWKS endpoint should return 200")

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			// ECDSA fields
			Crv string `json:"crv,omitempty"`
			X   string `json:"x,omitempty"`
			Y   string `json:"y,omitempty"`
			// RSA fields
			N string `json:"n,omitempty"`
			E string `json:"e,omitempty"`
		} `json:"keys"`
	}

	err := json.Unmarshal(response.ResponseRecorder.Body.Bytes(), &jwks)
	assert.NoError(t, err, "JWKS response should be valid JSON")

	keys := make(map[string]*JWKPublicKey)
	for _, key := range jwks.Keys {
		assert.Equal(t, "sig", key.Use, "Key use should be 'sig'")
		assert.NotEmpty(t, key.Kid, "Key ID should not be empty")
		assert.NotEmpty(t, key.Alg, "Algorithm should not be empty")

		var publicKey interface{}
		var algorithm types.SignAlgorithm

		if key.Kty == "EC" && key.Crv == "P-256" {
			algorithm = types.SignAlgES256
			xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
			assert.NoError(t, err, "Failed to decode ECDSA X coordinate")
			yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
			assert.NoError(t, err, "Failed to decode ECDSA Y coordinate")

			publicKey = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
		} else if key.Kty == "RSA" {
			algorithm = types.SignAlgRS256
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			assert.NoError(t, err, "Failed to decode RSA modulus")
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			assert.NoError(t, err, "Failed to decode RSA exponent")

			publicKey = &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: int(new(big.Int).SetBytes(eBytes).Int64()),
			}
		} else {
			t.Fatalf("Unsupported key type: %s", key.Kty)
		}

		keys[key.Kid] = &JWKPublicKey{
			Kid:       key.Kid,
			Algorithm: algorithm,
			PublicKey: publicKey,
		}
	}

	return keys
}

// VerifyJWTWithJWKS independently verifies JWT using JWKS public keys (without Auth server)
func VerifyJWTWithJWKS(t *testing.T, tokenString string, jwks map[string]*JWKPublicKey) *JWTClaims {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Extract kid from header
		kid, ok := token.Header["kid"].(string)
		assert.True(t, ok, "JWT should have kid in header")
		assert.NotEmpty(t, kid, "kid should not be empty")

		// Find public key in JWKS
		jwk, exists := jwks[kid]
		assert.True(t, exists, "kid should exist in JWKS: %s", kid)

		// Validate signing method matches the key algorithm
		var expectedMethod jwt.SigningMethod
		switch jwk.Algorithm {
		case types.SignAlgES256:
			expectedMethod = jwt.SigningMethodES256
		case types.SignAlgRS256:
			expectedMethod = jwt.SigningMethodRS256
		default:
			t.Fatalf("Unsupported algorithm in JWKS: %s", jwk.Algorithm)
		}

		assert.Equal(t, expectedMethod.Alg(), token.Method.Alg(),
			"JWT algorithm should match JWKS key algorithm")

		return jwk.PublicKey, nil
	})

	assert.NoError(t, err, "JWT verification should succeed")
	assert.True(t, token.Valid, "Token should be valid")

	claims, ok := token.Claims.(*JWTClaims)
	assert.True(t, ok, "Claims should be of correct type")

	return claims
}

// CreateTestSecretsProvider creates a dynamic secrets provider for testing key rotation/revocation
func CreateTestSecretsProvider(initialSecrets *types.InstanceSecrets) *TestSecretsProvider {
	return &TestSecretsProvider{
		secrets: initialSecrets,
	}
}

// TestSecretsProvider allows dynamic modification of secrets for testing
type TestSecretsProvider struct {
	secrets *types.InstanceSecrets
}

func (p *TestSecretsProvider) GetSecrets(instanceId string) (*types.InstanceSecrets, error) {
	return p.secrets, nil
}

func (p *TestSecretsProvider) UpdateSecrets(secrets *types.InstanceSecrets) {
	p.secrets = secrets
}

func (p *TestSecretsProvider) AddKey(kid string, key *types.SigningKey) {
	if p.secrets.Keys == nil {
		p.secrets.Keys = make(map[string]*types.SigningKey)
	}
	p.secrets.Keys[kid] = key
}

func (p *TestSecretsProvider) RemoveKey(kid string) {
	delete(p.secrets.Keys, kid)
}

func (p *TestSecretsProvider) SetPrimaryKey(kid string) {
	p.secrets.PrimaryKeyId = kid
}

type S map[string]any

// GenerateES256KeyPair generates an ES256 (ECDSA P-256) key pair for testing
func GenerateES256KeyPair() (privateKeyPEM string, publicKeyPEM string, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyBlock))

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

// GenerateRS256KeyPair generates an RS256 (RSA 2048) key pair for testing
func GenerateRS256KeyPair() (privateKeyPEM string, publicKeyPEM string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyBlock))

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

// GenerateTestSecrets creates test secrets with valid key pairs
func GenerateTestSecrets(algorithm types.SignAlgorithm) (*types.InstanceSecrets, error) {
	var privateKeyPEM, publicKeyPEM string
	var err error

	switch algorithm {
	case types.SignAlgES256:
		privateKeyPEM, publicKeyPEM, err = GenerateES256KeyPair()
	case types.SignAlgRS256:
		privateKeyPEM, publicKeyPEM, err = GenerateRS256KeyPair()
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, err
	}

	return &types.InstanceSecrets{
		PrimaryKeyId: "test-key",
		Keys: map[string]*types.SigningKey{
			"test-key": {
				Kid:        "test-key",
				Algorithm:  algorithm,
				PrivateKey: privateKeyPEM,
				PublicKey:  publicKeyPEM,
			},
		},
		AppSecret: "test-app-secret-fixed-for-hashid-consistency",
	}, nil
}
