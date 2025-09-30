import { ref, computed, onMounted, onUnmounted } from 'vue'
import type { AuthApi, Types } from '@cybersailor/slauth-ts'
import type { Localization } from '../types'
import { useErrorHandler } from './useErrorHandler'

/**
 * Auth composable for managing authentication state
 * Provides state management and error handling, but does not wrap every API method
 */
export function useAuth(authClient: AuthApi, localization?: Localization): {
  session: import('vue').ComputedRef<Types.Session | null>
  user: import('vue').ComputedRef<Types.User | null>
  loading: import('vue').ComputedRef<boolean>
  error: import('vue').ComputedRef<string | null>
  isAuthenticated: import('vue').ComputedRef<boolean>
  isLoading: import('vue').ComputedRef<boolean>
  initialize: () => Promise<void>
  updateSession: (authData: any) => void
  clearSession: () => void
  withLoadingAndError: <T>(operation: () => Promise<T>, options?: { updateSession?: boolean; clearErrorFirst?: boolean }) => Promise<T | null>
  handleError: (err: any) => string
  clearError: () => void
  authClient: AuthApi
} {
  const session = ref<Types.Session | null>(null)
  const user = ref<Types.User | null>(null)
  const loading = ref(false)

  // Use smart error handling
  const { error, handleError, clearError } = useErrorHandler(localization)

  // Computed properties
  const isAuthenticated = computed(() => !!session.value)
  const isLoading = computed(() => loading.value)

  // Initialize auth state
  const initialize = async () => {
    try {
      loading.value = true
      clearError()

      // Get current session from auth client
      const currentSession = authClient.getSession()
      session.value = currentSession
      user.value = currentSession?.user || null

      // Check if authenticated
      if (authClient.isAuthenticated()) {
        try {
          // Get fresh user data
          const userData = await authClient.getUser()
          user.value = userData.user || null
        } catch (userError) {
          // Failed to get user data should not block initialization
          console.warn('Failed to get user data:', userError)
        }
      }

      loading.value = false
    } catch (err) {
      console.error('Failed to initialize auth:', err)
      handleError(err)
      loading.value = false
    }
  }

  /**
   * Generic async operation wrapper
   * Automatically handles loading state and errors
   */
  const withLoadingAndError = async <T>(
    operation: () => Promise<T>,
    options: {
      updateSession?: boolean
      clearErrorFirst?: boolean
    } = {}
  ): Promise<T | null> => {
    try {
      loading.value = true
      if (options.clearErrorFirst !== false) {
        clearError()
      }

      const result = await operation()

      // If operation returned auth data, update local state
      if (options.updateSession && result && typeof result === 'object') {
        const authData = result as any
        if (authData.session) {
          session.value = authData.session
          user.value = authData.session.user || null
        }
      }

      return result
    } catch (err) {
      handleError(err)
      return null
    } finally {
      loading.value = false
    }
  }

  /**
   * Update local session state
   */
  const updateSession = (authData: any) => {
    if (authData?.session) {
      session.value = authData.session
      user.value = authData.session.user || null
    }
  }

  /**
   * Clear local session state
   */
  const clearSession = () => {
    session.value = null
    user.value = null
  }

  // Lifecycle
  onMounted(() => {
    initialize()
  })

  return {
    // State
    session: computed(() => session.value),
    user: computed(() => user.value),
    loading: computed(() => loading.value),
    error: computed(() => error.value),
    isAuthenticated,
    isLoading,

    // Core methods
    initialize,
    updateSession,
    clearSession,

    // Utility methods
    withLoadingAndError,
    handleError,
    clearError,

    // Directly expose authClient, let components call API directly
    authClient
  }
}