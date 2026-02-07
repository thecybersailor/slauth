/**
 * Slauth authentication adapter
 * Wraps @cybersailor/slauth-ts AuthApi to implement the AuthAdapter interface
 */

import type { AuthApi } from '@cybersailor/slauth-ts'
import type {
  AuthAdapter,
  AuthResult,
  Session,
  User,
  OAuthSignInParams,
  OAuthResult,
  SignInOptions,
  SignUpOptions
} from '../core/adapters/types'

/**
 * Create a Slauth authentication adapter
 * @param authClient - The slauth AuthApi client instance
 * @returns AuthAdapter implementation
 */
export function createSlauthAdapter(authClient: AuthApi): AuthAdapter {
  return {
    // ==================== Basic Authentication ====================
    
    async signInWithPassword(params: {
      email: string
      password: string
      options?: SignInOptions
    }): Promise<AuthResult> {
      const result = await authClient.signInWithPassword({
        email: params.email,
        password: params.password,
        options: params.options
      })
      
      return result as AuthResult
    },

    async signUp(params: {
      email: string
      password: string
      options?: SignUpOptions
    }): Promise<AuthResult> {
      const result = await authClient.signUp({
        email: params.email,
        password: params.password,
        options: params.options
      })
      
      return result as AuthResult
    },

    async signOut(): Promise<{ success?: boolean; error?: any }> {
      const result = await authClient.signOut()
      return result as { success?: boolean; error?: any }
    },

    // ==================== OAuth Authentication ====================
    
    async signInWithOAuth(params: OAuthSignInParams): Promise<OAuthResult> {
      const result = await authClient.signInWithOAuth({
        provider: params.provider,
        options: params.options,
        redirect_to: params.redirect_to
      })
      
      return result as OAuthResult
    },

    async exchangeCodeForSession(code: string): Promise<AuthResult> {
      const result = await authClient.exchangeCodeForSession(code)
      return result as AuthResult
    },

    // ==================== OTP Authentication ====================
    
    async signInWithOtp(params: {
      email?: string
      phone?: string
      options?: {
        captchaToken?: string
        channel?: string
        data?: Record<string, any>
        emailRedirectTo?: string
        redirect_to?: string
        shouldCreateUser?: boolean
      }
    }): Promise<{ messageId?: string; [key: string]: any }> {
      const result = await authClient.signInWithOtp({
        email: params.email,
        phone: params.phone,
        options: params.options
      })
      return result as { messageId?: string; [key: string]: any }
    },

    async verifyOtp(params: {
      email?: string
      phone?: string
      token: string
      options?: {
        captchaToken?: string
        redirect_to?: string
      }
      type?: string
    }): Promise<AuthResult> {
      const result = await authClient.verifyOtp({
        email: params.email,
        phone: params.phone,
        token: params.token,
        options: params.options,
        type: params.type || (params.email ? 'magiclink' : 'sms')
      })
      return result as AuthResult
    },

    // ==================== Password Management ====================
    
    async resetPasswordForEmail(email: string, options?: {
      captchaToken?: string
      redirect_to?: string
    }): Promise<{ messageId?: string; [key: string]: any }> {
      const result = await authClient.resetPasswordForEmail(email, options)
      return result as { messageId?: string; [key: string]: any }
    },

    async updatePassword(params: {
      password: string
      nonce?: string
    }): Promise<Record<string, any>> {
      return await authClient.updatePassword(params)
    },

    // ==================== Email Management ====================
    
    async updateEmail(params: { email: string }): Promise<{ success?: boolean; [key: string]: any }> {
      const result = await authClient.updateEmail(params)
      return result as { success?: boolean; [key: string]: any }
    },

    async verifyEmailChange(params: {
      email?: string
      phone?: string
      token: string
      options?: {
        captchaToken?: string
        redirect_to?: string
      }
      type?: string
    }): Promise<{ success?: boolean; [key: string]: any }> {
      const result = await authClient.verifyEmailChange(params)
      return result as { success?: boolean; [key: string]: any }
    },

    // ==================== Phone Management ====================
    
    async updatePhone(params: { phone: string }): Promise<{ success?: boolean; [key: string]: any }> {
      const result = await authClient.updatePhone(params)
      return result as { success?: boolean; [key: string]: any }
    },

    async verifyPhoneChange(params: {
      email?: string
      phone?: string
      token: string
      options?: {
        captchaToken?: string
        redirect_to?: string
      }
      type?: string
    }): Promise<{ success?: boolean; [key: string]: any }> {
      const result = await authClient.verifyPhoneChange(params)
      return result as { success?: boolean; [key: string]: any }
    },

    // ==================== Email Verification ====================
    
    async confirmEmail(token: string): Promise<void> {
      await authClient.confirmEmail(token)
    },

    // ==================== Session Management ====================
    
    getSession(): Session | null {
      return authClient.getSession() as Session | null
    },

    isAuthenticated(): boolean {
      return authClient.isAuthenticated()
    },

    async getUser(): Promise<{ user: User | null; error?: any }> {
      try {
        const result = await authClient.getUser()
        return {
          user: result.user as User | null,
          error: undefined
        }
      } catch (error: any) {
        return {
          user: null,
          error: error
        }
      }
    },

    async getSessions(): Promise<{
      sessions?: Array<{
        id?: string
        user_id?: string
        created_at?: string
        updated_at?: string
        refreshed_at?: string
        ip?: string
        user_agent?: string
        aal?: string
        [key: string]: any
      }>
      page?: number
      page_size?: number
      total?: number
      [key: string]: any
    }> {
      const result = await authClient.getSessions()
      return result as any
    },

    // ==================== MFA Management ====================
    
    async listMFAFactors(): Promise<{
      all?: Array<{
        id?: string
        type?: string
        status?: string
        friendly_name?: string
        created_at?: string
        updated_at?: string
        [key: string]: any
      }>
      totp?: Array<any>
      phone?: Array<any>
      [key: string]: any
    }> {
      const result = await authClient.listMFAFactors()
      return result as any
    },

    async enrollMFAFactor(params: {
      factorType?: string
      friendlyName?: string
      issuer?: string
      phone?: string
    }): Promise<{
      id?: string
      type?: string
      friendly_name?: string
      phone?: string
      totp?: {
        qr_code?: string
        secret?: string
        uri?: string
      }
      [key: string]: any
    }> {
      const result = await authClient.enrollMFAFactor({
        factorType: params.factorType as any,
        friendlyName: params.friendlyName,
        issuer: params.issuer,
        phone: params.phone
      })
      return result as any
    },

    async verifyMFAFactor(params: {
      challengeId?: string
      factorId?: string
      code?: string
    }): Promise<{
      access_token?: string
      refresh_token?: string
      token_type?: string
      expires_in?: number
      user?: User
      [key: string]: any
    }> {
      const result = await authClient.verifyMFAFactor(params)
      return result as any
    },

    async unenrollMFAFactor(factorId: string): Promise<{ id?: string; [key: string]: any }> {
      const result = await authClient.unenrollMFAFactor(factorId)
      return result as any
    },

    // ==================== Security & Audit ====================
    
    async getAuditLog(): Promise<{
      events?: Array<Record<string, any>>
      [key: string]: any
    }> {
      const result = await authClient.getAuditLog()
      return result as any
    },

    async getDevices(): Promise<{
      devices?: Array<Record<string, any>>
      [key: string]: any
    }> {
      const result = await authClient.getDevices()
      return result as any
    },

    // ==================== Session Management (Extended) ====================
    
    async revokeSession(sessionId: string): Promise<{ success?: boolean; [key: string]: any }> {
      const result = await authClient.revokeSession(sessionId)
      return result as { success?: boolean; [key: string]: any }
    },

    async revokeAllSessions(excludeCurrent?: boolean): Promise<{ success?: boolean; [key: string]: any }> {
      const result = await authClient.revokeAllSessions(excludeCurrent)
      return result as { success?: boolean; [key: string]: any }
    },

    // ==================== User Management ====================
    
    async updateUser(params: {
      email?: string
      phone?: string
      password?: string
      user_metadata?: Record<string, any>
      [key: string]: any
    }): Promise<{ user: User | null; error?: any }> {
      try {
        const result = await authClient.updateUser(params)
        return {
          user: result.user as User | null,
          error: undefined
        }
      } catch (error: any) {
        return {
          user: null,
          error: error
        }
      }
    },

    async resend(params: {
      email?: string
      phone?: string
      type?: string
      options?: {
        captchaToken?: string
        emailRedirectTo?: string
      }
    }): Promise<{ messageId?: string; [key: string]: any }> {
      const result = await authClient.resend({
        email: params.email,
        phone: params.phone,
        type: params.type,
        options: params.options
      })
      return result as { messageId?: string; [key: string]: any }
    }
  }
}

/**
 * Type guard to check if an adapter is a Slauth adapter
 */
export function isSlauthAdapter(adapter: any): adapter is ReturnType<typeof createSlauthAdapter> {
  return adapter && typeof adapter.signInWithPassword === 'function'
}
