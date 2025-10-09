import { createClients } from '@cybersailor/slauth-ts'
import mockProvider from '../providers/mock.vue'

console.log('[demo:auth.ts] Module loading/reloading', {
  timestamp: new Date().toISOString(),
  localStorage_keys: Object.keys(localStorage),
  session_exists: !!localStorage.getItem('aira.auth.token')
})

// Callback tracking for E2E tests
interface CallbackTracker {
  onSessionRefreshed: number
  onUnauthorized: number
  onAuthError: number
  lastRefreshedSession: any
  lastError: any
  callHistory: Array<{ type: string; timestamp: number; data?: any }>
}

// Initialize callback tracker on window for E2E testing
declare global {
  interface Window {
    __authCallbacks?: CallbackTracker
  }
}

if (typeof window !== 'undefined') {
  window.__authCallbacks = {
    onSessionRefreshed: 0,
    onUnauthorized: 0,
    onAuthError: 0,
    lastRefreshedSession: null,
    lastError: null,
    callHistory: []
  }
}

// Create the API clients
const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080'
export const { authClient, adminClient } = createClients({
  auth: { url: `${baseUrl}/auth` },
  admin: { url: `${baseUrl}/admin` },
  autoRefreshToken: true,
  persistSession: true,
  debug: true,
  onSessionRefreshed: (session) => {
    console.log('[demo:auth] onSessionRefreshed called', session)
    if (window.__authCallbacks) {
      window.__authCallbacks.onSessionRefreshed++
      window.__authCallbacks.lastRefreshedSession = session
      window.__authCallbacks.callHistory.push({
        type: 'onSessionRefreshed',
        timestamp: Date.now(),
        data: session
      })
    }
  },
  onUnauthorized: () => {
    console.log('[demo:auth] onUnauthorized called')
    if (window.__authCallbacks) {
      window.__authCallbacks.onUnauthorized++
      window.__authCallbacks.callHistory.push({
        type: 'onUnauthorized',
        timestamp: Date.now()
      })
    }
  },
  onAuthError: (error) => {
    console.log('[demo:auth] onAuthError called', error)
    if (window.__authCallbacks) {
      window.__authCallbacks.onAuthError++
      window.__authCallbacks.lastError = error
      window.__authCallbacks.callHistory.push({
        type: 'onAuthError',
        timestamp: Date.now(),
        data: error
      })
    }
  }
})

console.log('[demo:auth.ts] Clients created', {
  hasAuthClient: !!authClient,
  hasAdminClient: !!adminClient,
  callbacksEnabled: !!window.__authCallbacks
})

// Auth configuration for UI components
export const authConfig = {
  // Social providers configuration
  providers: ['google', 'google_pkce', 'github', 'facebook', 'twitter', mockProvider],
  
  // Redirect URLs
  redirectTo: `${window.location.origin}/dashboard`,
  authBaseUrl: `${window.location.origin}/auth`,
  
  // UI configuration
  appearance: 'default' as const,
  followRedirect: true,
  showLinks: true,
  magicLink: true,
  showForgotPassword: true,
  onlyThirdPartyProviders: false,
  
  // Debug mode
  debug: true
}

// Separate localization configuration
export const localizationConfig = {
  variables: {
    sign_in: {
      email_label: 'Email address',
      password_label: 'Password',
      button_label: 'Sign in',
      loading_button_label: 'Signing in ...',
      social_provider_text: 'Sign in with {{provider}}',
      link_text: "Don't have an account? Sign up"
    },
    sign_up: {
      email_label: 'Email address',
      password_label: 'Create a Password',
      button_label: 'Sign up',
      loading_button_label: 'Signing up ...',
      social_provider_text: 'Sign up with {{provider}}',
      link_text: 'Already have an account? Sign in'
    },
    magic_link: {
      email_label: 'Email address',
      button_label: 'Send magic link',
      loading_button_label: 'Sending magic link ...',
      link_text: 'Send a magic link email',
      confirmation_text: 'Check your email for the magic link'
    },
    forgotten_password: {
      email_label: 'Email address',
      button_label: 'Send reset instructions',
      loading_button_label: 'Sending reset instructions ...',
      link_text: 'Forgot your password?',
      confirmation_text: 'Check your email for the password reset link'
    },
    update_password: {
      password_label: 'New password',
      button_label: 'Update password',
      loading_button_label: 'Updating password ...',
      confirmation_text: 'Your password has been updated'
    },
    verify_otp: {
      email_label: 'Email address',
      token_label: 'Verification code',
      button_label: 'Verify',
      loading_button_label: 'Verifying ...'
    }
  }
}

