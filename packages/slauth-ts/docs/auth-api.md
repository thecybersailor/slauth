# AuthApi Reference

Authentication API client for user-facing operations.

## Security Flow Overview

For new integrations, prefer the secure identity-change APIs:

- `reauthenticate()`
- `verifyReauthentication()`
- `startEmailChange()`
- `verifyEmailChangeSecure()`
- `startPhoneChange()`
- `verifyPhoneChangeSecure()`

These methods support multi-step verification with `flow_id` and `session_code`.

The legacy helpers below remain available for compatibility:

- `updateEmail()` + `verifyEmailChange()`
- `updatePhone()` + `verifyPhoneChange()`

`updatePasswordWithFlow()` and `updatePassword()` both call the password update route. Password updates may require a higher AAL depending on server configuration.

## Methods

### createAuthError

```typescript
createAuthError(message: string): AuthError
```

### async

```typescript
async(): Promise<boolean> =>
```

### async

```typescript
async(): Promise<boolean> =>
```

### initializeSession

```typescript
initializeSession(): Promise<void>
```

### setSession

```typescript
setSession(session: Types.Session): Promise<void>
```

### clearSession

```typescript
clearSession(): Promise<void>
```

### signUp

```typescript
signUp(credentials: Types.SignUpRequest): Promise<Types.AuthData>
```

### signInWithPassword

```typescript
signInWithPassword(credentials: Types.SignInWithPasswordRequest): Promise<Types.AuthData>
```

### signInWithOtp

```typescript
signInWithOtp(credentials: Types.SignInWithOtpRequest): Promise<Types.SendOTPResponse>
```

### verifyOtp

```typescript
verifyOtp(params: Types.VerifyOtpRequest): Promise<Types.AuthData>
```

### signInWithIdToken

```typescript
signInWithIdToken(credentials: Types.SignInWithIdTokenRequest): Promise<Types.AuthData>
```

### signInWithSSO

```typescript
signInWithSSO(credentials: Types.SignInWithSSORequest): Promise<Types.SSOData>
```

### handleSSOCallback

```typescript
handleSSOCallback(params: any): Promise<Types.AuthData>
```

### signInWithOAuth

```typescript
signInWithOAuth(params: Types.SignInWithOAuthRequest): Promise<Types.OAuthData>
```

### exchangeCodeForSession

```typescript
exchangeCodeForSession(code: string): Promise<Types.AuthData>
```

### resend

```typescript
resend(params: Types.ResendRequest): Promise<Types.SendOTPResponse>
```

### resetPasswordForEmail

```typescript
resetPasswordForEmail(email: string, options?: Types.ResetPasswordOptions): Promise<Types.SendOTPResponse>
```

### sendSMSVerificationCode

```typescript
sendSMSVerificationCode(params: Types.SendSMSOTPRequest): Promise<Types.SendSMSOTPResponse>
```

### confirmEmail

```typescript
confirmEmail(token: string): Promise<Types.SuccessResponse>
```

### updatePasswordWithFlow

```typescript
updatePasswordWithFlow(params: Types.UpdatePasswordRequest): Promise<Types.UserResponse>
```

### getSession

```typescript
getSession(): Types.Session | null
```

### getUser

```typescript
getUser(): Promise<Types.UserData>
```

### updateUser

```typescript
updateUser(attributes: Types.UpdateUserRequest): Promise<Types.UserData>
```

### signOut

```typescript
signOut(options: Types.SignOutRequest = {}): Promise<Types.SuccessResponse>
```

### refreshSession

```typescript
refreshSession(): Promise<Types.AuthData>
```

### updatePassword

```typescript
updatePassword(request: Types.UpdatePasswordRequest): Promise<Record<string, any>>
```

### reauthenticate

```typescript
reauthenticate(request: Types.ReauthenticateRequest = {}): Promise<Types.ReauthenticateData>
```

### verifyReauthentication

```typescript
verifyReauthentication(request: Types.VerifyReauthenticateRequest): Promise<Types.ReauthenticateVerifyData>
```

### updateEmail

```typescript
updateEmail(request: { email: string }): Promise<Types.SendOTPResponse>
```

### updatePhone

```typescript
updatePhone(request: { phone: string }): Promise<Types.SendOTPResponse>
```

### verifyEmailChange

```typescript
verifyEmailChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse>
```

### verifyPhoneChange

```typescript
verifyPhoneChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse>
```

### startEmailChange

```typescript
startEmailChange(request: Types.StartEmailChangeRequest): Promise<Types.IdentityChangeData>
```

### verifyEmailChangeSecure

```typescript
verifyEmailChangeSecure(request: Types.VerifyIdentityChangeRequest): Promise<Types.IdentityChangeData>
```

### startPhoneChange

```typescript
startPhoneChange(request: Types.StartPhoneChangeRequest): Promise<Types.IdentityChangeData>
```

### verifyPhoneChangeSecure

```typescript
verifyPhoneChangeSecure(request: Types.VerifyIdentityChangeRequest): Promise<Types.IdentityChangeData>
```

## Secure Email And Phone Change Pattern

Typical secure change flow:

1. Call `startEmailChange()` or `startPhoneChange()`
2. Store the returned `flow_id`, `session_code`, and `stage`
3. Call the matching secure verify method with the verification token
4. If the response returns `completed: false`, continue with the returned `stage` and `session_code`
5. Finish when the response returns `completed: true`

Legacy change helpers still return `session_code`, and clients should pass it explicitly when calling the matching legacy verify method.

### getSessions

```typescript
getSessions(): Promise<Types.ListSessionsResponse>
```

### revokeSession

```typescript
revokeSession(sessionId: string): Promise<Types.SuccessResponse>
```

### revokeAllSessions

```typescript
revokeAllSessions(excludeCurrent: boolean = false): Promise<Types.SuccessResponse>
```

### getAuditLog

```typescript
getAuditLog(): Promise<Types.GetAuditLogResponse>
```

### getDevices

```typescript
getDevices(): Promise<Types.GetDevicesResponse>
```

### enrollMFAFactor

```typescript
enrollMFAFactor(params: Types.MFAEnrollRequest): Promise<Types.MFAEnrollData>
```

### challengeMFAFactor

```typescript
challengeMFAFactor(params: { factorId: string }): Promise<Types.MFAChallengeData>
```

### verifyMFAFactor

```typescript
verifyMFAFactor(params: Types.MFAVerifyRequest): Promise<Types.MFAVerifyData>
```

### unenrollMFAFactor

```typescript
unenrollMFAFactor(factorId: string): Promise<Types.MFAUnenrollData>
```

### listMFAFactors

```typescript
listMFAFactors(): Promise<Types.MFAListFactorsData>
```
