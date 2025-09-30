# @cybersailor/slauth-ui-vue

Vue 3 UI components for slauth.

## Installation

```bash
npm install @cybersailor/slauth-ui-vue @cybersailor/slauth-ts
```

## Quick Start

```vue
<template>
  <div>
    <Auth
      :auth-client="authClient"
      appearance="default"
      theme="light"
      :providers="['google', 'github']"
      redirect-to="http://localhost:3000/auth/callback"
    />
  </div>
</template>

<script setup lang="ts">
import { createClient } from '@cybersailor/slauth-ts'
import { Auth } from '@cybersailor/slauth-ui-vue'
import '@cybersailor/slauth-ui-vue/style.css'

const authClient = createClient({
  url: 'http://localhost:8080',
  apiKey: 'your-api-key'
})
</script>
```

## Components

### Auth

The main authentication component that provides a complete auth flow.

```vue
<Auth
  :auth-client="authClient"
  appearance="default"
  theme="light"
  :providers="['google', 'github']"
  redirect-to="http://localhost:3000/auth/callback"
  :localization="{
    sign_up: {
      email_label: 'Email address',
      password_label: 'Create a Password'
    }
  }"
  @event="handleAuthEvent"
/>
```

### Props

- `authClient` - slauth client instance
- `appearance` - UI appearance theme (`'default'` | `'minimal'`)
- `theme` - Color theme (`'light'` | `'dark'` | `'auto'`)
- `providers` - OAuth providers to show
- `redirectTo` - URL to redirect after authentication
- `localization` - Custom text labels
- `showLinks` - Show sign up/sign in links
- `view` - Initial view (`'sign_in'` | `'sign_up'` | `'magic_link'` | `'forgotten_password'`)

### Events

- `@event` - Emitted on auth state changes

## Styling

The components come with default styling that can be customized:

```css
/* Import default styles */
@import '@cybersailor/slauth-ui-vue/style.css';

/* Customize variables */
:root {
  --auth-ui-primary: #3b82f6;
  --auth-ui-primary-hover: #2563eb;
  --auth-ui-border: #e5e7eb;
  --auth-ui-background: #ffffff;
  --auth-ui-text: #111827;
}
```

## Features

- ✅ Email/Password Authentication
- ✅ OAuth Providers (Google, GitHub, etc.)
- ✅ Magic Link Authentication
- ✅ Password Recovery
- ✅ Multi-Factor Authentication (MFA)
- ✅ Responsive Design
- ✅ Dark/Light Theme Support
- ✅ Customizable Styling
- ✅ TypeScript Support
- ✅ Vue 3 Composition API

## License

MIT
