# AuthApi Reference

Authentication API client for user-facing operations.

## Methods

### createAuthError

```typescript
createAuthError(message: string): AuthError
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

### updateEmail

```typescript
updateEmail(request: { email: string }): Promise<Types.SuccessResponse>
```

### updatePhone

```typescript
updatePhone(request: { phone: string }): Promise<Types.SuccessResponse>
```

### verifyEmailChange

```typescript
verifyEmailChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse>
```

### verifyPhoneChange

```typescript
verifyPhoneChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse>
```

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
