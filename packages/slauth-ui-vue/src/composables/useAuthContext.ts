import { inject, computed } from 'vue'
import type { AuthContext } from '../components/AuthConfig.vue'

// Composable for using auth context
export function useAuthContext(): AuthContext {
  const context = inject<{ value: AuthContext }>('auth-context')

  if (!context) {
    throw new Error('useAuthContext must be used within an AuthConfig component')
  }

  return context.value
}

// Helper for getting OAuth callback URL
export function useOAuthCallbackUrl(): string {
  const { authConfig } = useAuthContext()
  return `${authConfig.authBaseUrl}/callback`
}

// Helper for getting user redirect URL
export function useUserRedirectUrl(): string {
  const { authConfig } = useAuthContext()
  return authConfig.redirectTo || '/'
}

// Helper for getting localization config
export function useLocalization() {
  const { localization } = useAuthContext()
  return localization || {}
}

// Helper for getting dark mode state
export function useDarkMode() {
  const { darkMode } = useAuthContext()
  return darkMode || false
}
