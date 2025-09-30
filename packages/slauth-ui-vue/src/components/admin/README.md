# Admin Components

Admin panel component library, implemented based on AdminApi.

## Architecture Design

### AdminLayout.vue
Top-level admin panel layout component that passes context down through **provide/inject**:
- `adminClient`: AdminApi instance
- `localization`: Internationalization configuration
- `darkMode`: Dark mode state

### useAdminContext
All child components get context through `useAdminContext()`, no props passing needed.

## Component List

### 1. User Management
- List display of all users
- Create new users
- Edit user information
- Delete users

### 2. Identity Management (SAML SSO)
- List display of SAML Providers
- Create/Edit/Delete Providers
- Test Providers

### 3. Session Management
- View active sessions
- Revoke single/all sessions

### 4. System Stats
- Display system key metrics
- User count, session count and other statistics

### 5. Settings
- Authentication settings
- Password policies
- Rate limiting

## Usage Examples

### Basic Usage

```vue
<template>
  <AdminLayout
    :admin-client="adminClient"
    :localization="localization"
    :dark-mode="darkMode"
    :tabs="['stats', 'users', 'sso', 'session', 'settings']"
  />
</template>

<script setup lang="ts">
import { AdminLayout } from '@cybersailor/slauth-ui-vue'
import { AdminApi } from '@cybersailor/slauth-ts'

const adminClient = new AdminApi('http://localhost:3000', {})

// Set admin session
adminClient.setSession(currentUserSession)

const localization = {
  admin: {
    stats: 'Statistics',
    users: 'Users',
    sso: 'SSO',
    session: 'Sessions',
    settings: 'Settings'
  }
}

const darkMode = false
</script>
```

### Usage in Child Components

```vue
<script setup lang="ts">
import { useAdminContext } from '@cybersailor/slauth-ui-vue'

// Automatically get context, no props needed
const { adminClient, localization, darkMode } = useAdminContext()

// Use adminClient
const users = await adminClient.listUsers()
</script>
```

## Configuration Options

### AdminLayout Props

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| adminClient | AdminApi | - | Admin API instance (required) |
| localization | Localization | {} | Internationalization configuration |
| darkMode | boolean | false | Dark mode |
| tabs | string[] | ['stats', 'users', 'sso', 'session', 'settings'] | Displayed tabs |

## Theme Variables

Supports custom CSS variables, consistent with Auth component:

```css
--admin-bg: Background color
--admin-text: Text color
--admin-border: Border color
--admin-brand: Brand color
--admin-brand-accent: Brand accent color
--admin-space: Spacing
--admin-radius: Border radius
--admin-font: Font
```

## Internationalization Configuration

Supports configuring admin panel text through `localization.admin`:

```typescript
localization: {
  admin: {
    title: 'Admin Panel',
    dashboard: 'Dashboard',
    users: 'Users',
    sessions: 'Sessions',
    saml: 'SAML SSO',
    stats: 'Statistics',
    logout: 'Logout',
    // ... more configurations
  }
}
```

## Automated Testing Support

All major operation elements have `data-testid` attributes added:

```typescript
// User Management
'admin-users-create-button'
'admin-users-edit-button'
'admin-users-delete-button'

// SAML SSO
'admin-sso-create-button'
'admin-sso-test-button'

// Sessions
'admin-session-revoke-button'
'admin-session-revoke-all-button'

// Settings
'admin-settings-save-button'
'admin-settings-reset-button'
```

See [IMPLEMENTATION.md](./IMPLEMENTATION.md) for details

## Development Standards

1. All components use TypeScript
2. Use Composition API
3. Follow Vue 3 best practices
4. Component naming uses PascalCase
5. File naming uses PascalCase.vue
6. Unified error handling mechanism
7. Unified loading state management
8. Unified confirmation dialogs
9. No Tailwind CSS, use CSS variables
10. Support theme variables and dark mode
11. Support internationalization configuration
