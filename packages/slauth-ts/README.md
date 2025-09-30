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

## License

MIT
