import { inject } from 'vue'
import { useAuthContext } from './useAuthContext'
import { getRedirectParameter } from '../lib/redirectManager'

/**
 * Common OAuth sign-in handler for all providers
 * Automatically handles redirect_to from URL or config
 */
export function useOAuthSignIn() {
  const { authClient, authConfig } = useAuthContext()
  const authState = inject<any>('authState', null)

  /**
   * Initiate OAuth sign-in flow
   * @param provider Provider name (e.g. 'google', 'mock')
   * @param options Provider-specific options (e.g. redirect_uri, scope)
   */
  const signInWithOAuth = async (provider: string, options?: Record<string, string>): Promise<any> => {
    authState?.setLoading(`oauth.${provider}`)

    const redirectTo = getRedirectParameter() || authConfig.redirectTo

    return authClient.signInWithOAuth({
      provider,
      options,
      redirect_to: redirectTo
    })
  }

  return {
    signInWithOAuth
  }
}

