package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flaboy/pin"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

type TestHelper struct {
	DB            *gorm.DB
	Router        *gin.Engine
	TestDomain    string
	EmailProvider *MockEmailProvider
	SMSProvider   *MockSMSProvider
}

func NewTestHelper(db *gorm.DB, router *gin.Engine, domain string, emailProvider *MockEmailProvider, smsProvider *MockSMSProvider) *TestHelper {
	return &TestHelper{
		DB:            db,
		Router:        router,
		TestDomain:    domain,
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
	assert.NotNil(t, rsp.Response.Error, msg+": Response should be an error")
	assert.Contains(t, rsp.Response.Error.Key, errorField, msg+": Error should contain: %s", errorField)
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

type S map[string]any
