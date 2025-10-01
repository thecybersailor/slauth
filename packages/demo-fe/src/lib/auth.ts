import { createClients } from '@cybersailor/slauth-ts'

// Create the API clients
const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080'
export const { authClient, adminClient } = createClients({
  auth: { url: `${baseUrl}/auth` },
  admin: { url: `${baseUrl}/admin` },
  autoRefreshToken: true,
  persistSession: true,
  debug: true,
})

// Auth configuration for UI components
export const authConfig = {
  // Social providers configuration
  providers: ['google', 'google_pkce', 'github', 'facebook', 'twitter'],
  
  // Redirect URLs
  redirectTo: `${window.location.origin}/dashboard`,
  authBaseUrl: 'http://localhost:5180/auth',
  
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

