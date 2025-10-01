# Pin Response Format & Testing Cheatsheet

## Pin Response Structure

```go
type Response struct {
    Data    interface{}            `json:"data,omitempty"`
    Meta    map[string]interface{} `json:"meta,omitempty"`
    TraceId string                 `json:"trace_id,omitempty"`
    Error   *ResponseError         `json:"error,omitempty"`
}

type ResponseError struct {
    Message string `json:"message,omitempty"`
    Type    string `json:"type,omitempty"`
    Key     string `json:"key,omitempty"`
}
```

Reference: https://raw.githubusercontent.com/flaboy/pin/refs/heads/main/response.go

## HTTP Status Code Rules

### Access Token Scenarios → 401
- Invalid JWT token
- Expired access token
- Missing Authorization header
- Access token validation failure

### All Other Scenarios → 200
- Refresh token errors (returns 200 with error in response body)
- Session expired (returns 200 with error in response body)
- Invalid credentials (returns 200 with error in response body)
- Validation errors (returns 200 with error in response body)
- All application-level errors (returns 200 with Error object)

## Test Assertion Methods

### HasError - Assert Error Response
```go
// Check if response contains expected error
suite.helper.HasError(suite.T(), response, "refresh_token_not_found")
suite.helper.HasError(suite.T(), response, "session_expired")
suite.helper.HasError(suite.T(), response, "invalid_credentials")
```

### MatchObject - Assert Success Response
```go
// Verify response data structure
suite.helper.MatchObject(suite.T(), response, S{
    "user": S{
        "email": "test@example.com",
        "id":    "abc123",
    },
    "session": S{
        "access_token":  "not_empty",
        "refresh_token": "not_empty",
    },
})
```

### Status Code Assertion
```go
// For access token errors
suite.Equal(401, response.ResponseRecorder.Code)

// For all other errors  
suite.Equal(200, response.ResponseRecorder.Code)
suite.NotNil(response.Response.Error)
```

## Common Test Patterns

### Pattern 1: Test Refresh Token Error
```go
// Step 1: Make refresh request with invalid token
refreshRequest := S{
    "grant_type":    "refresh_token",
    "refresh_token": "invalid_token",
}
response := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)

// Step 2: Assert 200 status with error in body
suite.Equal(200, response.ResponseRecorder.Code)
suite.helper.HasError(suite.T(), response, "refresh_token_not_found")
```

### Pattern 2: Test Session Expired
```go
// Step 1: Revoke session
revokeHeaders := map[string]string{
    "Authorization": "Bearer " + accessToken,
}
revokeResponse := suite.helper.MakeDELETERequest(suite.T(), "/auth/sessions/"+sessionId, nil, revokeHeaders)

// Step 2: Try to use refresh token
refreshResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token?grant_type=refresh_token", refreshRequest)

// Step 3: Assert 200 with session_expired error
suite.Equal(200, refreshResponse.ResponseRecorder.Code)
suite.helper.HasError(suite.T(), refreshResponse, "session_expired")
```

### Pattern 3: Test Access Token Validation
```go
// Step 1: Make request with invalid/expired access token
userResponse := suite.helper.MakeGETRequestWithAuth(suite.T(), "/auth/user", "invalid_token")

// Step 2: Assert 401 status
suite.Equal(401, userResponse.ResponseRecorder.Code)
```

### Pattern 4: Test Success Response
```go
// Step 1: Make valid request
loginResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/token", loginRequestBody)

// Step 2: Assert 200 with data
suite.Equal(200, loginResponse.ResponseRecorder.Code)
suite.Nil(loginResponse.Response.Error)
suite.helper.MatchObject(suite.T(), loginResponse, S{
    "session": S{
        "access_token": "not_empty",
    },
})
```

## Error Handling in Controllers

### Return Error Directly
```go
func (a *AuthController) RefreshToken(c *pin.Context) error {
    refreshTokenRecord, err := a.authService.ValidateRefreshToken(c.Request.Context(), req.RefreshToken)
    if err != nil {
        return err  // Returns 200 with error in response body
    }
    // ... success logic
}
```

### Access Token Validation
```go
// Middleware automatically returns 401 for invalid access tokens
// No manual status code setting needed
```

## Checklist
- [ ] Use HasError for error assertions (status code 200)
- [ ] Use MatchObject for success data assertions
- [ ] Only expect 401 for access token validation failures
- [ ] All other errors return 200 with Error object
- [ ] Return errors directly from controllers (no status code setting)

## Files
- Test helpers: tests/helpers_test.go
- Error constants: pkg/consts/errors.go
- Controller examples: pkg/controller/*.go

## Reference Code
- tests/helpers_test.go:203-206 (HasError implementation)
- tests/helpers_test.go:208-218 (MatchObject implementation)
- tests/17-token-revocation-best-practices_test.go (test patterns)
- pkg/controller/token_handlers.go (controller error handling)

## Test Cases
- tests/16-token-error-scenarios_test.go
- tests/17-token-revocation-best-practices_test.go
- tests/05-session-management_test.go

## Search Keywords
- `suite\.helper\.HasError` - Find error assertion usage
- `suite\.helper\.MatchObject` - Find success assertion usage
- `ResponseRecorder\.Code` - Find status code assertions
- `Response\.Error` - Find error object checks
- `return.*consts\.` - Find controller error returns
- `401.*Unauthorized` - Find access token validation
- `200.*response\.ResponseRecorder\.Code` - Find 200 status assertions

