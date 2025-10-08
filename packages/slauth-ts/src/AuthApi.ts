import { createHttpClient } from './lib/fetch'
import { createValidatedHttpClient, ValidatedApiClient } from './lib/validated-client'
import { StorageManager } from './lib/storage'
import { AuthError } from './lib/errors'
import * as Schemas from './schemas/auth-api.schemas'
import * as Types from './types/auth-api'

/** Auth API client - handles authentication operations */
export class AuthApi {
  public request: any           
  private api: ValidatedApiClient  
  private storage: StorageManager
  private autoRefreshToken: boolean
  private persistSession: boolean
  private currentSession: Types.Session | null = null
  private currentUser: any = null

  private createAuthError(message: string): AuthError {
    return { message, key: 'UNAUTHORIZED' }
  }

  constructor(baseURL: string, config: any) {
    this.storage = new StorageManager(config.storage)
    this.autoRefreshToken = config.autoRefreshToken !== false
    this.persistSession = config.persistSession !== false
    
    // Create clients first without refresh function
    this.api = createValidatedHttpClient({
      baseURL,
      ...config
    })
    
    this.request = createHttpClient({
      baseURL: '', 
      ...config
    })
    
    // Create refresh token function that uses this.api
    const refreshTokenFn = async (): Promise<boolean> => {
      if (!this.currentSession?.refresh_token) {
        return false
      }
      
      const requestBody = {
        refresh_token: this.currentSession.refresh_token
      }
      
      const { data, error } = await this.api.postWithValidation<Types.AuthData>(
        '/token?grant_type=refresh_token',
        requestBody,
        Schemas.RefreshTokenRequestSchema,
        Schemas.AuthDataSchema
      )
      
      if (error || !data || !data.session) {
        return false
      }
      
      await this.setSession(data.session as Types.Session)
      config.onSessionRefreshed?.(data.session)
      return true
    }
    
    // Set refresh function if auto refresh is enabled
    if (this.autoRefreshToken) {
      (this.api as any).config.refreshTokenFn = refreshTokenFn;
      (this.request as any).config.refreshTokenFn = refreshTokenFn
    }
    
    this.syncTokenState()
    this.initializeSession()
  }

  private syncTokenState() {
    
    const originalSetAuth = this.api.setAuth.bind(this.api)
    this.api.setAuth = (token: string | null) => {
      originalSetAuth(token)
      this.request.setAuth(token)
    }
  }

  private async initializeSession(): Promise<void> {
    if (!this.persistSession) return

    try {
      const session = await this.storage.getSession()
      if (session) {
        this.currentSession = session
        this.currentUser = session.user
        this.api.setAuth(session.access_token)
      }
    } catch (error) {
      console.warn('[slauth] Failed to initialize session:', error)
    }
  }

  /**
   * Set session for the client
   * IMPORTANT: This method updates the same object reference to maintain synchronization
   * with AdminApi. When adminClient.setSession(authClient.getSession()) is called,
   * both clients share the same session object reference. By using Object.assign()
   * instead of reassigning, token refreshes and session updates automatically propagate
   * to all clients holding the reference.
   */
  private async setSession(session: Types.Session): Promise<void> {
    // Update existing session object to maintain reference synchronization
    if (this.currentSession) {
      Object.assign(this.currentSession, session)
    } else {
      this.currentSession = session
    }
    
    this.currentUser = session.user
    if (!session.access_token) {
      throw new Error('No access token in session')
    }
    this.api.setAuth(session.access_token)

    if (this.persistSession) {
      await this.storage.saveSession(session)
      await this.storage.saveUser(session.user)
    }
  }

  private async clearSession(): Promise<void> {
    this.currentSession = null
    this.currentUser = null
    this.api.setAuth(null)

    if (this.persistSession) {
      await this.storage.removeSession()
      await this.storage.removeUser()
    }
  }

  // Authentication methods
  async signUp(credentials: Types.SignUpRequest): Promise<Types.AuthData> {
    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/signup',
      credentials,
      Schemas.SignUpRequestSchema.refine(
        (data) => data.email || data.phone,
        { message: "Either email or phone is required" }
      ),
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
    }

    return data
  }

  async signInWithPassword(credentials: Types.SignInWithPasswordRequest): Promise<Types.AuthData> {
    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/token?grant_type=password',
      credentials,
      Schemas.SignInWithPasswordRequestSchema.refine(
        (data) => data.email || data.phone,
        { message: "Either email or phone is required" }
      ),
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
    }

    return data
  }

  async signInWithOtp(credentials: Types.SignInWithOtpRequest): Promise<Types.SendOTPResponse> {
    const { data, error } = await this.api.postWithValidation<Types.SendOTPResponse>(
      '/otp',
      credentials,
      Schemas.SignInWithOtpRequestSchema.refine(
        (data) => data.email || data.phone,
        { message: "Either email or phone is required" }
      ),
      Schemas.SendOTPResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async verifyOtp(params: Types.VerifyOtpRequest): Promise<Types.AuthData> {
    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/verify',
      params,
      Schemas.VerifyOtpRequestSchema,
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
    }

    return data
  }

  async signInWithIdToken(credentials: Types.SignInWithIdTokenRequest): Promise<Types.AuthData> {
    const requestBody = {
      grant_type: 'id_token',
      id_token: credentials.credential,
      provider: credentials.provider
    }

    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/token',
      requestBody,
      undefined, // No specific schema for this request body
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
    }

    return data
  }

  async signInWithSSO(credentials: Types.SignInWithSSORequest): Promise<Types.SSOData> {
    const requestBody = {
      provider_id: credentials.providerId,
      instance: credentials.instance,
      redirect_to: credentials.options?.redirectTo
    }

    const { data, error } = await this.api.postWithValidation<Types.SSOData>(
      '/sso',
      requestBody,
      undefined, // No specific schema for this request body
      Schemas.SSODataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async handleSSOCallback(params: any): Promise<Types.AuthData> {
    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/sso/callback',
      params,
      undefined, // No specific schema for this request
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
    }

    return data
  }

  async signInWithOAuth(params: Types.SignInWithOAuthRequest): Promise<Types.OAuthData> {
    
    const { generateCodeVerifier } = await import('./lib/pkce')
    const codeVerifier = generateCodeVerifier()

    
    localStorage.setItem('pkce_code_verifier', codeVerifier)

    const requestBody: any = {
      provider: params.provider,
      options: params.options || {}
    }

    if (params.redirect_to) {
      requestBody.redirect_to = params.redirect_to
    }

    const { data, error } = await this.api.postWithValidation<Types.OAuthData>(
      '/authorize',
      requestBody,
      undefined, // No specific schema for this request
      Schemas.OAuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async exchangeCodeForSession(code: string): Promise<Types.AuthData> {
    const urlParams = new URLSearchParams(window.location.search)
    const state = urlParams.get('state')

    
    const codeVerifier = localStorage.getItem('pkce_code_verifier')

    if (!codeVerifier) {
      return Promise.reject({
        message: 'Code verifier not found. Please restart the OAuth flow.',
        key: 'pkce_code_verifier_missing'
      })
    }

    const requestBody: Types.ExchangeCodeRequest = {
      auth_code: code,
      code_verifier: codeVerifier,
      ...(state && { flow_id: state })
    }

    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/token?grant_type=pkce',
      requestBody,
      Schemas.ExchangeCodeRequestSchema,
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
      
      localStorage.removeItem('pkce_code_verifier')
    }

    return data
  }

  async resend(params: Types.ResendRequest): Promise<Types.SendOTPResponse> {
    const { data, error } = await this.api.postWithValidation<Types.SendOTPResponse>(
      '/resend',
      params,
      Schemas.ResendRequestSchema,
      Schemas.SendOTPResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async resetPasswordForEmail(email: string, options?: Types.ResetPasswordOptions): Promise<Types.SendOTPResponse> {
    const requestBody: Types.ResetPasswordRequest = {
      email,
      ...(options && { options })
    }

    const { data, error } = await this.api.postWithValidation<Types.SendOTPResponse>(
      '/recover',
      requestBody,
      Schemas.ResetPasswordRequestSchema,
      Schemas.SendOTPResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // Public routes - no authentication required
  async sendSMSVerificationCode(params: Types.SendSMSOTPRequest): Promise<Types.SendSMSOTPResponse> {
    const { data, error } = await this.api.postWithValidation<Types.SendSMSOTPResponse>(
      '/sms-otp',
      params,
      Schemas.SendSMSOTPRequestSchema,
      Schemas.SendSMSOTPResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async confirmEmail(token: string): Promise<Types.SuccessResponse> {
    const { data, error } = await this.api.getWithValidation<Types.SuccessResponse>(
      `/confirm?token=${encodeURIComponent(token)}`,
      Schemas.SuccessResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async updatePasswordWithFlow(params: Types.UpdatePasswordRequest): Promise<Types.UserResponse> {
    const { data, error } = await this.api.putWithValidation<Types.UserResponse>(
      '/user/password',
      params,
      Schemas.UpdatePasswordRequestSchema,
      Schemas.UserResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // Session management
  getSession(): Types.Session | null {
    return this.currentSession
  }

  getAuthState() {
    return { session: this.currentSession, user: this.currentUser }
  }

  isAuthenticated() {
    return this.currentSession !== null
  }

  // User management methods (merged from UserApi)
  async getUser(): Promise<Types.UserData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.getWithValidation<Types.UserData>(
      '/user',
      Schemas.UserDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async updateUser(attributes: Types.UpdateUserRequest): Promise<Types.UserData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.putWithValidation<Types.UserData>(
      '/user',
      attributes,
      Schemas.UpdateUserRequestSchema,
      Schemas.UserDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    // Update current user
    if (data.user) {
      this.currentUser = { ...this.currentUser, ...data.user }
    }

    return data
  }

  async signOut(options: Types.SignOutRequest = {}): Promise<Types.SuccessResponse> {
    const { data, error } = await this.api.postWithValidation<Types.SuccessResponse>(
      '/logout',
      { scope: options.scope },
      Schemas.SignOutRequestSchema,
      Schemas.SuccessResponseSchema
    )

    // Clear session regardless of API response
    await this.clearSession()

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async refreshSession(): Promise<Types.AuthData> {
    if (!this.currentSession?.refresh_token) {
      return Promise.reject({
        message: 'No refresh token',
        key: 'no_refresh_token'
      })
    }

    const requestBody: Types.RefreshTokenRequest = {
      refresh_token: this.currentSession.refresh_token
    }

    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/token?grant_type=refresh_token',
      requestBody,
      Schemas.RefreshTokenRequestSchema,
      Schemas.AuthDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.setSession(data.session as Types.Session)
    }

    return data
  }

  async updatePassword(request: Types.UpdatePasswordRequest): Promise<Record<string, any>> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.put('/password', request)

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data || {}
  }

  async updateEmail(request: { email: string }): Promise<Types.SuccessResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.putWithValidation<Types.SuccessResponse>(
      '/email',
      request,
      Schemas.UpdateUserRequestSchema,
      Schemas.SuccessResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async updatePhone(request: { phone: string }): Promise<Types.SuccessResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.putWithValidation<Types.SuccessResponse>(
      '/phone',
      request,
      Schemas.UpdateUserRequestSchema,
      Schemas.SuccessResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // Email and phone verification methods
  async verifyEmailChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.postWithValidation<Types.SuccessResponse>(
      '/email/verify',
      params,
      Schemas.VerifyOtpRequestSchema,
      Schemas.SuccessResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async verifyPhoneChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.postWithValidation<Types.SuccessResponse>(
      '/phone/verify',
      params,
      Schemas.VerifyOtpRequestSchema,
      Schemas.SuccessResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // Session management methods
  async getSessions(): Promise<Types.ListSessionsResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.getWithValidation<Types.ListSessionsResponse>(
      '/sessions',
      Schemas.ListSessionsResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async revokeSession(sessionId: string): Promise<Types.SuccessResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { error } = await this.api.delete(`/sessions/${sessionId}`)
    if (error) return Promise.reject(error)
    return { success: true }
  }

  async revokeAllSessions(excludeCurrent: boolean = false): Promise<Types.SuccessResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const params = new URLSearchParams()
    if (excludeCurrent) {
      params.append('exclude_current', 'true')
    }

    const url = params.toString() ? `/sessions?${params.toString()}` : '/sessions'
    const { error } = await this.api.delete(url)
    if (error) return Promise.reject(error)
    return { success: true }
  }

  // Security methods
  async getAuditLog(): Promise<Types.GetAuditLogResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.getWithValidation<Types.GetAuditLogResponse>(
      '/security/audit-log',
      Schemas.GetAuditLogResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async getDevices(): Promise<Types.GetDevicesResponse> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.getWithValidation<Types.GetDevicesResponse>(
      '/security/devices',
      Schemas.GetDevicesResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // MFA methods
  async enrollMFAFactor(params: Types.MFAEnrollRequest): Promise<Types.MFAEnrollData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.postWithValidation<Types.MFAEnrollData>(
      '/factors/enroll',
      params,
      Schemas.MFAEnrollRequestSchema,
      Schemas.MFAEnrollDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async challengeMFAFactor(params: { factorId: string }): Promise<Types.MFAChallengeData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.postWithValidation<Types.MFAChallengeData>(
      '/factors/challenge',
      { factorId: params.factorId },
      undefined,
      Schemas.MFAChallengeDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async verifyMFAFactor(params: Types.MFAVerifyRequest): Promise<Types.MFAVerifyData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.postWithValidation<Types.MFAVerifyData>(
      '/factors/verify',
      params,
      Schemas.MFAVerifyRequestSchema,
      Schemas.MFAVerifyDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    // Update session if verification successful
    if (data.user) {
      // Create a session-like object for setSession
      const sessionData = {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        token_type: data.token_type,
        expires_in: data.expires_in,
        user: data.user
      } as Types.Session

      await this.setSession(sessionData)
    }

    return data
  }

  async unenrollMFAFactor(factorId: string): Promise<Types.MFAUnenrollData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { error } = await this.api.delete(`/factors/${factorId}`)
    if (error) return Promise.reject(error)
    return { id: factorId }
  }

  async listMFAFactors(): Promise<Types.MFAListFactorsData> {
    if (!this.currentSession) {
      return Promise.reject(this.createAuthError('No session'))
    }

    const { data, error } = await this.api.getWithValidation<Types.MFAListFactorsData>(
      '/factors',
      Schemas.MFAListFactorsDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }
}
