# AdminApi Reference

Admin API client for user management operations.

## Methods

### setSession

Set session for admin operations (typically from authClient) IMPORTANT: This stores a reference to the session object, not a copy. When called with authClient.getSession(), both clients will share the same session object. This enables automatic synchronization - when authClient refreshes the token, the changes propagate automatically to adminClient because AuthApi.setSession() uses Object.assign() to update the same object. Usage: adminClient.setSession(authClient.getSession())

```typescript
setSession(session: Session): void
```

### clearSession

Clear current session

```typescript
clearSession(): void
```

### getToken

Get current access token

```typescript
getToken(): string | null
```

### isAuthenticated

Check if admin client is authenticated

```typescript
isAuthenticated(): boolean
```

### getSession

Get current session

```typescript
getSession(): Session | null
```

### createSAMLProvider

```typescript
createSAMLProvider(provider: Types.CreateSAMLProviderRequest): Promise<Types.SAMLProviderResponse>
```

### listSAMLProviders

```typescript
listSAMLProviders(): Promise<Types.ListSAMLProvidersResponse>
```

### getSAMLProvider

```typescript
getSAMLProvider(id: string): Promise<Types.SAMLProviderResponse>
```

### updateSAMLProvider

```typescript
updateSAMLProvider(id: string, provider: Types.UpdateSAMLProviderRequest): Promise<Types.SAMLProviderResponse>
```

### deleteSAMLProvider

```typescript
deleteSAMLProvider(id: string): Promise<void>
```

### testSAMLProvider

```typescript
testSAMLProvider(id: string): Promise<void>
```

### queryUsers

Query users with filters, sorting, and pagination

```typescript
queryUsers(params?: {
    filters?: Record<string, any>
    sort?: string[]
    pagination?: {
      page?: number
      pageSize?: number
    }
  }): Promise<Types.ListUsersResponse>
```

### listUsers

List all users (simple query without filters)

```typescript
listUsers(): Promise<Types.ListUsersResponse>
```

### getUser

```typescript
getUser(id: string): Promise<Types.AdminUserResponse>
```

### updateUser

```typescript
updateUser(id: string, updates: Types.AdminUpdateUserRequest): Promise<Types.AdminUserResponse>
```

### deleteUser

```typescript
deleteUser(id: string): Promise<void>
```

### createUser

```typescript
createUser(userData: Types.AdminCreateUserRequest): Promise<Types.AdminUserResponse>
```

### resetUserPassword

```typescript
resetUserPassword(userId: string, passwordData: Types.AdminResetPasswordRequest): Promise<void>
```

### setUserEmailConfirmed

```typescript
setUserEmailConfirmed(userId: string, confirmed: boolean): Promise<void>
```

### setUserPhoneConfirmed

```typescript
setUserPhoneConfirmed(userId: string, confirmed: boolean): Promise<void>
```

### listAllSessions

```typescript
listAllSessions(): Promise<Types.ListSessionsResponse>
```

### listUserSessions

```typescript
listUserSessions(userId: string): Promise<Types.ListSessionsResponse>
```

### revokeSession

```typescript
revokeSession(sessionId: string): Promise<void>
```

### revokeAllUserSessions

```typescript
revokeAllUserSessions(userId: string): Promise<void>
```

### listUserIdentities

```typescript
listUserIdentities(userId: string): Promise<any>
```

### deleteUserIdentity

```typescript
deleteUserIdentity(userId: string, identityId: string): Promise<void>
```

### getUserCount

```typescript
getUserCount(): Promise<Types.StatsResponse>
```

### getActiveSessionCount

```typescript
getActiveSessionCount(): Promise<Types.SessionStatsResponse>
```

### getRecentSignups

```typescript
getRecentSignups(): Promise<any>
```

### getRecentSignins

```typescript
getRecentSignins(): Promise<any>
```

### getInstanceConfig

Get instance configuration

```typescript
getInstanceConfig(): Promise<
```
