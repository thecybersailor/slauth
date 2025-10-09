# Composables Reference

## useAdminContext

```typescript
function useAdminContext(): ComputedRef<AdminContext>
```

## useAuth

Auth composable for managing authentication state Provides state management and error handling, but does not wrap every API method

```typescript
function useAuth(authClient: AuthApi, localization?: Localization): 
```

## useAuthContext

```typescript
function useAuthContext(): AuthContext
```
