# User Management Components

This directory contains Vue components for post-authentication user management functionality.

## Components Overview

| Component | Description | API Endpoints |
|-----------|-------------|---------------|
| `UserProfile.vue` | Display and edit user profile information | `GET /user`, `PUT /user` |
| `PasswordManagement.vue` | Change user password | `PUT /password` |
| `EmailManagement.vue` | Change email address with verification | `PUT /email`, `POST /email/verify` |
| `PhoneManagement.vue` | Change phone number with verification | `PUT /phone`, `POST /phone/verify` |
| `MFAManagement.vue` | Manage two-factor authentication | `POST /factors/enroll`, `GET /factors`, `DELETE /factors/:id` |
| `SessionManagement.vue` | View and manage active sessions | `GET /sessions`, `DELETE /sessions/:id`, `DELETE /sessions` |
| `SecurityAudit.vue` | View security events and trusted devices | `GET /security/audit-log`, `GET /security/devices` |
| `UserDashboard.vue` | Complete user management interface | Combines all above components |

## Design Principles

All components follow these principles:

### 1. Testability
- Every interactive element has a `data-testid` attribute
- Consistent naming convention for test selectors
- Support for E2E testing scenarios

### 2. Internationalization
- Full i18n support with English defaults
- Localized error messages and user feedback
- Customizable text for all user-facing elements

### 3. Theme Support
- Dark/light theme compatibility
- CSS custom properties for consistent theming
- Responsive design for all screen sizes

### 4. Reusable UI Components
- Built using shared UI components from `../ui/`
- Consistent styling and behavior
- Accessible design patterns

### 5. Error Handling
- No try-catch blocks (following project standards)
- No fallback mechanisms
- Direct error propagation with user-friendly messages

## Usage Patterns

### Individual Component Usage
```vue
<template>
  <UserProfile
    :auth-client="authClient"
    :localization="localization"
    @auth-event="handleAuthEvent"
  />
</template>

<script setup>
import { UserProfile } from '@cybersailor/slauth-ui-vue'
</script>
```

### Complete Dashboard Usage
```vue
<template>
  <UserDashboard
    :auth-client="authClient"
    :localization="localization"
    @auth-event="handleAuthEvent"
  />
</template>

<script setup>
import { UserDashboard } from '@cybersailor/slauth-ui-vue'
</script>
```

## Event Handling

All components emit `auth-event` with standardized event structure:

```typescript
interface AuthEvent {
  event: string
  session?: Session | null
  error?: string
  email?: string
  phone?: string
  data?: any
}
```

### Event Types
- `profile_updated` - User profile changes
- `password_updated` - Password changes
- `email_updated` / `phone_updated` - Contact info changes
- `mfa_enrolled` / `mfa_unenrolled` - 2FA changes
- `session_revoked` / `all_sessions_revoked` - Session management

## API Integration

Components use the `AuthApi` client from `@cybersailor/slauth-ts` package:

```typescript
// User management methods
authClient.getUser()
authClient.updateUser()
authClient.updatePassword()
authClient.updateEmail()
authClient.verifyEmailChange()
authClient.updatePhone()
authClient.verifyPhoneChange()
authClient.enrollMFAFactor()
authClient.listMFAFactors()
authClient.verifyMFAFactor()
authClient.unenrollMFAFactor()
authClient.getSessions()
authClient.revokeSession()
authClient.revokeAllSessions()
authClient.getAuditLog()
authClient.getDevices()
```

## Localization Structure

Each component has its own localization section:

```typescript
interface Localization {
  user_profile?: { ... }
  password_management?: { ... }
  email_management?: { ... }
  phone_management?: { ... }
  mfa_management?: { ... }
  session_management?: { ... }
  security_audit?: { ... }
  user_dashboard?: { ... }
}
```

## Testing

All components include comprehensive test selectors:

```javascript
// Example test selectors
await page.getByTestId('user-profile-form')
await page.getByTestId('password-new-input')
await page.getByTestId('email-verify-button')
await page.getByTestId('mfa-qr-code')
await page.getByTestId('session-item')
await page.getByTestId('audit-event')
```

## File Structure

```
user-management/
├── index.ts                 # Component exports
├── README.md               # This file
├── UserProfile.vue         # Profile management
├── PasswordManagement.vue  # Password changes
├── EmailManagement.vue     # Email changes
├── PhoneManagement.vue     # Phone changes
├── MFAManagement.vue       # 2FA management
├── SessionManagement.vue   # Session management
├── SecurityAudit.vue       # Security events
└── UserDashboard.vue       # Complete dashboard
```

This organization provides a clear separation between authentication (pre-login) and user management (post-login) components while maintaining consistency in design and implementation patterns.
