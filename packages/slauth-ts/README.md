# @cybersailor/slauth-ts

Official TypeScript client library for slauth.

## Installation

```bash
npm install @cybersailor/slauth-ts
```

## Quick Start

```typescript
import { createClient } from '@cybersailor/slauth-ts'

const auth = createClient({
  url: 'http://localhost:8080',
  apiKey: 'your-api-key'
})

// Sign up
const { data, error } = await auth.signUp({
  email: 'user@example.com',
  password: 'Password123!'
})

// Sign in
const { data, error } = await auth.signInWithPassword({
  email: 'user@example.com',
  password: 'Password123!'
})

// Listen to auth changes
auth.onAuthStateChange((event, session) => {
  console.log(event, session)
})
```

## Features

- ✅ Email/Password Authentication
- ✅ OAuth Providers (Google, GitHub, etc.)
- ✅ OTP Authentication
- ✅ Multi-Factor Authentication (MFA)
- ✅ Session Management
- ✅ Auto Token Refresh
- ✅ Automatic Token Injection for API Calls
- ✅ TypeScript Support

## API Reference

### Authentication Methods

- `signUp(credentials)` - Create a new user account
- `signInWithPassword(credentials)` - Sign in with email/password
- `signInWithOtp(credentials)` - Sign in with OTP
- `signInWithOAuth(provider)` - Sign in with OAuth provider
- `signOut()` - Sign out current user
- `refreshSession()` - Refresh current session

### User Management

- `getUser()` - Get current user
- `updateUser(attributes)` - Update user attributes
- `getSession()` - Get current session

### MFA Methods

- `mfa.enroll(params)` - Enroll MFA factor
- `mfa.challenge(params)` - Create MFA challenge
- `mfa.verify(params)` - Verify MFA challenge
- `mfa.listFactors()` - List user's MFA factors

## Making API Calls with Automatic Token Management

When building your application, you'll need to make authenticated API calls to your backend. Instead of manually managing access tokens and handling token refresh, you can use `authClient.request` which automatically:

- **Attaches the access token** to all requests
- **Refreshes expired tokens** automatically when receiving 401 errors
- **Retries failed requests** after successful token refresh
- **Synchronizes token state** with the auth session

### Basic Usage

Replace your axios calls with `authClient.request`:

```typescript
import { createClients } from '@cybersailor/slauth-ts'

const { authClient } = createClients({
  auth: { url: 'http://localhost:8080/auth' },
  autoRefreshToken: true, // Enable automatic token refresh
  persistSession: true,
  // Optional: coordinate refresh automatically
  // - Browser: uses navigator.locks when available
  // - Node/Bun: falls back to an in-process async mutex (not cross-process)
  // crossTabRefreshLock: false,
  // refreshLockKey: 'slauth:refresh:my-app',
})

// After user signs in
await authClient.signInWithPassword({
  email: 'user@example.com',
  password: 'Password123!'
})

// Use authClient.request instead of axios for your API calls
// The access token is automatically attached to the request
const response = await authClient.request.get('/api/user/profile')
const userProfile = response.data

// POST request with automatic token injection
const createResult = await authClient.request.post('/api/orders', {
  productId: '123',
  quantity: 2
})

// PUT, PATCH, DELETE are also supported
await authClient.request.put('/api/user/settings', { theme: 'dark' })
await authClient.request.patch('/api/user/preferences', { notifications: true })
await authClient.request.delete('/api/user/data')
```

### Migration from Axios

If you're currently using axios, the migration is straightforward:

```typescript
// ❌ Before: Manual token management
const response = await axios.get('/api/user/profile', {
  headers: {
    Authorization: `Bearer ${accessToken}`
  }
})

// ✅ After: Automatic token management
const response = await authClient.request.get('/api/user/profile')
```

### How It Works

1. **Token Injection**: When you call `authClient.request.get()`, `post()`, etc., the current access token from the session is automatically added to the `Authorization` header.

2. **Automatic Refresh**: If the API returns a 401 Unauthorized error:
   - The SDK automatically attempts to refresh the token using the refresh token
   - If refresh succeeds, the original request is retried automatically
   - Your application code doesn't need to handle token refresh logic

3. **Session Synchronization**: The `request` client is synchronized with the auth session. When tokens are refreshed, both the auth session and the request client are updated automatically.

### Error Handling

The request client supports callback functions for handling authentication errors:

```typescript
const { authClient } = createClients({
  auth: { url: 'http://localhost:8080/auth' },
  autoRefreshToken: true,
  onUnauthorized: () => {
    // Called when token refresh fails or user is not authenticated
    console.log('User session expired')
    // Redirect to login page
    window.location.href = '/login'
  },
  onSessionRefreshed: (session) => {
    // Called when token is successfully refreshed
    console.log('Session refreshed', session)
  },
  onAuthError: (error) => {
    // Called for general authentication errors
    console.error('Auth error:', error)
  }
})
```

### Request Options

The request methods accept the same options as axios:

```typescript
// GET with query parameters
const response = await authClient.request.get('/api/users', {
  params: {
    page: 1,
    limit: 10
  }
})

// POST with custom headers
const result = await authClient.request.post('/api/upload', formData, {
  headers: {
    'Content-Type': 'multipart/form-data'
  },
  timeout: 30000
})
```

### Full Example

```typescript
import { createClients } from '@cybersailor/slauth-ts'

// Initialize clients
const { authClient } = createClients({
  auth: { url: 'http://localhost:8080/auth' },
  autoRefreshToken: true,
  persistSession: true,
  onUnauthorized: () => {
    // Handle session expiration
    router.push('/login')
  }
})

// Sign in
const { data } = await authClient.signInWithPassword({
  email: 'user@example.com',
  password: 'Password123!'
})

// Make authenticated API calls
async function fetchUserData() {
  const response = await authClient.request.get('/api/user/profile')
  return response.data
}

async function updateUserProfile(updates: any) {
  const response = await authClient.request.put('/api/user/profile', updates)
  return response.data
}

async function createOrder(orderData: any) {
  const response = await authClient.request.post('/api/orders', orderData)
  return response.data
}
```

## License

MIT
