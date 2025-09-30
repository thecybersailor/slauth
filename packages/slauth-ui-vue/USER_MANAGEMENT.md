# User Management Components

This document describes the user management components available in `@cybersailor/slauth-ui-vue` for handling post-login user operations.

## Directory Structure

User management components are organized in a dedicated subdirectory:

```
src/components/
├── user-management/          # Post-login user management components
│   ├── index.ts             # Component exports
│   ├── UserProfile.vue      # User profile management
│   ├── PasswordManagement.vue
│   ├── EmailManagement.vue
│   ├── PhoneManagement.vue
│   ├── MFAManagement.vue
│   ├── SessionManagement.vue
│   ├── SecurityAudit.vue
│   └── UserDashboard.vue    # Complete dashboard
├── Auth.vue                 # Main authentication component
├── SignIn.vue              # Pre-login components
├── SignUp.vue
└── ui/                     # Shared UI components
```

## Overview

The user management components provide a complete interface for users to manage their accounts after authentication. All components are built with the same design principles as the authentication components:

- **Testability**: All components include `data-testid` attributes for E2E testing
- **Internationalization**: Full i18n support with English defaults
- **Theme Support**: Dark/light theme compatibility
- **Reusable UI**: Built using shared UI components

## Available Components

### 1. UserProfile.vue
Displays and allows editing of user profile information.

**Features:**
- View current email and phone (read-only)
- Edit user metadata (JSON format)
- Automatic form validation
- Success/error messaging

**Usage:**
```vue
<UserProfile
  :auth-client="authClient"
  :localization="localization"
  @auth-event="handleAuthEvent"
/>
```

### 2. PasswordManagement.vue
Handles password changes with validation.

**Features:**
- New password input with confirmation
- Password strength validation
- Form validation and error handling
- Success confirmation

**Usage:**
```vue
<PasswordManagement
  :auth-client="authClient"
  :localization="localization"
  @auth-event="handleAuthEvent"
/>
```

### 3. EmailManagement.vue
Manages email address changes with verification.

**Features:**
- Two-step process: send code → verify
- Email format validation
- Verification code input
- Success confirmation

**Usage:**
```vue
<EmailManagement
  :auth-client="authClient"
  :localization="localization"
  :current-email="user?.email"
  @auth-event="handleAuthEvent"
/>
```

### 4. PhoneManagement.vue
Manages phone number changes with SMS verification.

**Features:**
- Two-step process: send SMS → verify
- Phone format validation
- Verification code input
- Success confirmation

**Usage:**
```vue
<PhoneManagement
  :auth-client="authClient"
  :localization="localization"
  :current-phone="user?.phone"
  @auth-event="handleAuthEvent"
/>
```

### 5. MFAManagement.vue
Manages two-factor authentication setup.

**Features:**
- List current MFA factors
- Enroll new TOTP/phone factors
- QR code display for TOTP setup
- Factor removal
- Verification process

**Usage:**
```vue
<MFAManagement
  :auth-client="authClient"
  :localization="localization"
  @auth-event="handleAuthEvent"
/>
```

### 6. SessionManagement.vue
Manages active user sessions.

**Features:**
- List all active sessions
- Device and location information
- Session revocation (individual/all)
- Current session highlighting

**Usage:**
```vue
<SessionManagement
  :auth-client="authClient"
  :localization="localization"
  @auth-event="handleAuthEvent"
/>
```

### 7. SecurityAudit.vue
Displays security audit logs and trusted devices.

**Features:**
- Security event timeline
- Trusted device list
- Event details (IP, location, device)
- Time formatting

**Usage:**
```vue
<SecurityAudit
  :auth-client="authClient"
  :localization="localization"
  @auth-event="handleAuthEvent"
/>
```

### 8. UserDashboard.vue
Complete user management interface combining all components.

**Features:**
- Integrated layout with collapsible sections
- Profile information section
- Security settings grid
- Session management
- Security audit
- Responsive design

**Usage:**
```vue
<UserDashboard
  :auth-client="authClient"
  :localization="localization"
  @auth-event="handleAuthEvent"
/>
```

## Props Interface

All user management components share common props:

```typescript
interface BaseUserManagementProps {
  /** slauth client instance */
  authClient: AuthApi
  /** UI localization */
  localization?: Localization
  /** Custom CSS classes */
  className?: string
}
```

## Events

All components emit `auth-event` with the following structure:

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

- `profile_updated` - User profile information updated
- `password_updated` - Password changed successfully
- `email_verification_sent` - Email verification code sent
- `email_updated` - Email address updated
- `phone_verification_sent` - Phone verification code sent
- `phone_updated` - Phone number updated
- `mfa_enrollment_started` - MFA enrollment process started
- `mfa_enrolled` - MFA factor enrolled successfully
- `mfa_unenrolled` - MFA factor removed
- `session_revoked` - Individual session revoked
- `all_sessions_revoked` - All sessions revoked

## Localization

All components support full internationalization. The localization object includes sections for each component:

```typescript
interface Localization {
  user_profile?: {
    title?: string
    email_label?: string
    phone_label?: string
    metadata_label?: string
    save_button_label?: string
    loading_button_label?: string
    success_message?: string
  }
  password_management?: {
    title?: string
    current_password_label?: string
    new_password_label?: string
    confirm_password_label?: string
    // ... more fields
  }
  // ... other component localizations
}
```

## Example Usage

```vue
<template>
  <div class="user-settings">
    <UserDashboard
      :auth-client="authClient"
      :localization="localization"
      @auth-event="handleAuthEvent"
    />
  </div>
</template>

<script setup>
import { AuthApi, createClients } from '@cybersailor/slauth-ts'
import { UserDashboard } from '@cybersailor/slauth-ui-vue'

// Or import individual components
// import { UserProfile, PasswordManagement } from '@cybersailor/slauth-ui-vue'

// Create auth client
const { authClient } = createClients({
  baseURL: 'http://localhost:8080',
  autoRefreshToken: true,
  persistSession: true
})

// Custom localization
const localization = {
  user_dashboard: {
    title: 'Account Settings',
    profile_section_title: 'Personal Information'
  },
  // ... other localizations
}

// Handle events
const handleAuthEvent = (event) => {
  console.log('Auth event:', event)
  // Handle different event types
}
</script>
```

## Testing

All components include `data-testid` attributes for E2E testing:

```javascript
// Example test selectors
const userProfile = await page.getByTestId('user-profile-form')
const passwordInput = await page.getByTestId('password-new-input')
const emailVerifyButton = await page.getByTestId('email-verify-button')
const mfaQrCode = await page.getByTestId('mfa-qr-code')
const sessionItem = await page.getByTestId('session-item')
```

## Styling

Components use Tailwind CSS classes and support dark mode:

```css
/* Dark mode support is built-in */
.aira-user-profile {
  @apply bg-white dark:bg-gray-800;
}
```

## Error Handling

Components follow the project's error handling principles:
- No try-catch blocks
- No fallback mechanisms
- Direct error propagation
- User-friendly error messages via localization

## API Integration

All components use the `AuthApi` client from `@cybersailor/slauth-ts` package:

```typescript
// Available methods used by components
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

This provides a complete user management solution that integrates seamlessly with the existing authentication flow.
