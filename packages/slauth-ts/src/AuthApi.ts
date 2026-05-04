import { createHttpClient, HttpClient } from './lib/fetch'
import { createValidatedHttpClient, ValidatedApiClient } from './lib/validated-client'
import { AuthError } from './lib/errors'
import { debugLog } from './lib/helpers'
import { SessionManager } from './lib/session-manager'
import * as Schemas from './schemas/auth-api.schemas'
import * as Types from './types/auth-api'

/** Auth API client - handles authentication operations */
export class AuthApi {
  public request: HttpClient
  private api: ValidatedApiClient
  private debug: boolean
  private sessionManager: SessionManager
  private readonly derivedRequestClients = new Map<string, HttpClient>()

  private createAuthError(message: string): AuthError {
    return { message, key: 'UNAUTHORIZED' }
  }

  constructor(baseURL: string, config: any, sessionManager?: SessionManager) {
    this.debug = config.debug || false
    debugLog(this.debug, '[slauth:AuthApi] Constructor called', {
      baseURL,
      autoRefreshToken: config.autoRefreshToken !== false,
      persistSession: config.persistSession !== false,
      hasCustomStorage: !!config.storage,
      storageKey: config.storageKey,
      debug: this.debug
    })

    this.sessionManager =
      sessionManager ??
      new SessionManager({
        authBaseURL: baseURL,
        apiKey: config.apiKey,
        headers: config.headers,
        autoRefreshToken: config.autoRefreshToken,
        persistSession: config.persistSession,
        storage: config.storage,
        storageKey: config.storageKey,
        crossTabRefreshLock: config.crossTabRefreshLock,
        refreshLockKey: config.refreshLockKey,
        debug: config.debug,
        timeout: config.timeout,
        onSessionRefreshed: config.onSessionRefreshed
      })

    this.api = createValidatedHttpClient({
      refreshTokenFn: async () => (await this.sessionManager.refreshSession()) !== null,
      baseURL,
      ...config
    })
    this.sessionManager.bindRefreshClient(this.api)

    this.request = createHttpClient({
      refreshTokenFn: async () => (await this.sessionManager.refreshSession()) !== null,
      baseURL: '',
      ...config
    })

    this.syncTokenState()
    queueMicrotask(() => {
      void this.sessionManager.initialize()
    })
  }

  private syncTokenState() {
    debugLog(this.debug, '[slauth:AuthApi] syncTokenState called')
    this.sessionManager.registerTokenConsumer((token) => {
      debugLog(this.debug, '[slauth:AuthApi] token consumer called', {
        hasToken: !!token,
        tokenPreview: token ? `${token.substring(0, 20)}...` : null
      })
      this.api.setAuth(token)
      this.request.setAuth(token)
    })
  }

  createRequestClient(options: { baseURL: string }): HttpClient {
    const normalizedBaseURL = String(options.baseURL || '').trim()
    const cached = this.derivedRequestClients.get(normalizedBaseURL)
    if (cached) {
      return cached
    }

    const client = this.request.createDerivedClient({ baseURL: normalizedBaseURL })
    this.sessionManager.registerTokenConsumer((token) => {
      client.setAuth(token)
    })
    this.derivedRequestClients.set(normalizedBaseURL, client)
    return client
  }

  private async requireSession(): Promise<Types.Session> {
    const session = await this.sessionManager.getSession()
    if (!session) {
      throw this.createAuthError('No session')
    }
    return session
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
      await this.sessionManager.setSession(data.session as Types.Session)
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
      await this.sessionManager.setSession(data.session as Types.Session)
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
      await this.sessionManager.setSession(data.session as Types.Session)
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
      await this.sessionManager.setSession(data.session as Types.Session)
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
      await this.sessionManager.setSession(data.session as Types.Session)
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
      await this.sessionManager.setSession(data.session as Types.Session)
      
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
      '/password',
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
  async getSession(): Promise<Types.Session | null> {
    return this.sessionManager.getSession()
  }

  async getAuthState() {
    const session = await this.sessionManager.getSession()
    return { session, user: session?.user ?? null }
  }

  async isAuthenticated(): Promise<boolean> {
    return this.sessionManager.hasSession()
  }

  // User management methods (merged from UserApi)
  async getUser(): Promise<Types.UserData> {
    await this.requireSession()

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
    await this.requireSession()

    const { data, error } = await this.api.putWithValidation<Types.UserData>(
      '/user',
      attributes,
      Schemas.UpdateUserRequestSchema,
      Schemas.UserDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.user) {
      const session = await this.requireSession()
      await this.sessionManager.setSession({
        ...session,
        user: { ...session.user, ...data.user }
      })
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
    await this.sessionManager.clearSession()

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async refreshSession(): Promise<Types.AuthData> {
    const session = await this.requireSession()
    if (!session.refresh_token) {
      return Promise.reject({
        message: 'No refresh token',
        key: 'no_refresh_token'
      })
    }

    const requestBody: Types.RefreshTokenRequest = {
      refresh_token: session.refresh_token
    }

    // Mark this request to skip auto refresh to prevent infinite loop
    const { data, error } = await this.api.postWithValidation<Types.AuthData>(
      '/token?grant_type=refresh_token',
      requestBody,
      Schemas.RefreshTokenRequestSchema,
      Schemas.AuthDataSchema,
      { _skipAutoRefresh: true } as any
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    if (data.session) {
      await this.sessionManager.setSession(data.session as Types.Session)
    }

    return data
  }

  async updatePassword(request: Types.UpdatePasswordRequest): Promise<Record<string, any>> {
    await this.requireSession()

    const { data, error } = await this.api.put('/password', request)

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data || {}
  }

  async reauthenticate(request: Types.ReauthenticateRequest = {}): Promise<Types.ReauthenticateData> {
    await this.requireSession()

    const { data, error } = await this.api.postWithValidation<Types.ReauthenticateData>(
      '/reauthenticate',
      request,
      Schemas.ReauthenticateRequestSchema,
      Schemas.ReauthenticateDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async verifyReauthentication(request: Types.VerifyReauthenticateRequest): Promise<Types.ReauthenticateVerifyData> {
    await this.requireSession()

    const { data, error } = await this.api.postWithValidation<Types.ReauthenticateVerifyData>(
      '/reauthenticate/verify',
      request,
      Schemas.VerifyReauthenticateRequestSchema,
      Schemas.ReauthenticateVerifyDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async updateEmail(request: { email: string }): Promise<Types.SendOTPResponse> {
    await this.requireSession()

    const { data, error } = await this.api.putWithValidation<Types.SendOTPResponse>(
      '/email',
      request,
      Schemas.UpdateUserRequestSchema,
      Schemas.SendOTPResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async updatePhone(request: { phone: string }): Promise<Types.SendOTPResponse> {
    await this.requireSession()

    const { data, error } = await this.api.putWithValidation<Types.SendOTPResponse>(
      '/phone',
      request,
      Schemas.UpdateUserRequestSchema,
      Schemas.SendOTPResponseSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // Email and phone verification methods
  async verifyEmailChange(params: Types.VerifyOtpRequest): Promise<Types.SuccessResponse> {
    await this.requireSession()

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
    await this.requireSession()

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

  async startEmailChange(request: Types.StartEmailChangeRequest): Promise<Types.IdentityChangeData> {
    await this.requireSession()

    const { data, error } = await this.api.postWithValidation<Types.IdentityChangeData>(
      '/email/change',
      request,
      Schemas.StartEmailChangeRequestSchema,
      Schemas.IdentityChangeDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async verifyEmailChangeSecure(request: Types.VerifyIdentityChangeRequest): Promise<Types.IdentityChangeData> {
    await this.requireSession()

    const { data, error } = await this.api.postWithValidation<Types.IdentityChangeData>(
      '/email/change/verify',
      request,
      Schemas.VerifyIdentityChangeRequestSchema,
      Schemas.IdentityChangeDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async startPhoneChange(request: Types.StartPhoneChangeRequest): Promise<Types.IdentityChangeData> {
    await this.requireSession()

    const { data, error } = await this.api.postWithValidation<Types.IdentityChangeData>(
      '/phone/change',
      request,
      Schemas.StartPhoneChangeRequestSchema,
      Schemas.IdentityChangeDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  async verifyPhoneChangeSecure(request: Types.VerifyIdentityChangeRequest): Promise<Types.IdentityChangeData> {
    await this.requireSession()

    const { data, error } = await this.api.postWithValidation<Types.IdentityChangeData>(
      '/phone/change/verify',
      request,
      Schemas.VerifyIdentityChangeRequestSchema,
      Schemas.IdentityChangeDataSchema
    )

    if (error || !data) {
      return Promise.reject(error || { message: 'No data returned', key: 'no_data' })
    }

    return data
  }

  // Session management methods
  async getSessions(): Promise<Types.ListSessionsResponse> {
    await this.requireSession()

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
    await this.requireSession()

    const { error } = await this.api.delete(`/sessions/${sessionId}`)
    if (error) return Promise.reject(error)
    return { success: true }
  }

  async revokeAllSessions(excludeCurrent: boolean = false): Promise<Types.SuccessResponse> {
    await this.requireSession()

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
    await this.requireSession()

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
    await this.requireSession()

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
    await this.requireSession()

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
    await this.requireSession()

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
    await this.requireSession()

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

      await this.sessionManager.setSession(sessionData)
    }

    return data
  }

  async unenrollMFAFactor(factorId: string): Promise<Types.MFAUnenrollData> {
    await this.requireSession()

    const { error } = await this.api.delete(`/factors/${factorId}`)
    if (error) return Promise.reject(error)
    return { id: factorId }
  }

  async listMFAFactors(): Promise<Types.MFAListFactorsData> {
    await this.requireSession()

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
