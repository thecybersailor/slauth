/**
 * Core authentication adapter interface
 * This interface abstracts the authentication backend, allowing different implementations
 */

/** Sign in options */
export interface SignInOptions {
  captchaToken?: string
  redirect_to?: string
}

/** Sign up options */
export interface SignUpOptions {
  captchaToken?: string
  channel?: string
  data?: Record<string, any>
  emailRedirectTo?: string
  redirect_to?: string
  shouldCreateUser?: boolean
}

/** OAuth sign in parameters */
export interface OAuthSignInParams {
  provider: string
  options?: Record<string, string>
  redirect_to?: string
}

/** OAuth result (redirect-based flow) */
export interface OAuthResult {
  url?: string
  [key: string]: any
}

/** User information */
export interface User {
  id: string
  email?: string
  phone?: string
  user_metadata?: Record<string, any>
  app_metadata?: Record<string, any>
  [key: string]: any
}

/** Session information */
export interface Session {
  user: User
  access_token: string
  refresh_token?: string
  expires_at?: number
  expires_in?: number
  token_type?: string
  [key: string]: any
}

/** Authentication result */
export interface AuthResult {
  session?: Session | null
  user?: User | null
  redirect_to?: string
  [key: string]: any
}

/**
 * Authentication adapter interface
 * All authentication backends must implement this interface
 */
export interface AuthAdapter {
  // ==================== Basic Authentication ====================
  
  /**
   * Sign in with email and password
   */
  signInWithPassword(params: {
    email: string
    password: string
    options?: SignInOptions
  }): Promise<AuthResult>

  /**
   * Sign up with email and password
   */
  signUp(params: {
    email: string
    password: string
    options?: SignUpOptions
  }): Promise<AuthResult>

  /**
   * Sign out current user
   */
  signOut(): Promise<{ success?: boolean; error?: any }>

  // ==================== OAuth Authentication ====================
  
  /**
   * Sign in with OAuth provider (redirect-based)
   * Returns redirect URL or throws error
   */
  signInWithOAuth(params: OAuthSignInParams): Promise<OAuthResult>

  /**
   * Exchange OAuth code for session (PKCE callback)
   */
  exchangeCodeForSession(code: string): Promise<AuthResult>

  // ==================== OTP Authentication ====================
  
  /**
   * Sign in with OTP (magic link / email OTP)
   */
  signInWithOtp(params: {
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
  }): Promise<{ messageId?: string; [key: string]: any }>

  /**
   * Verify OTP
   */
  verifyOtp(params: {
    email?: string
    phone?: string
    token: string
    options?: {
      captchaToken?: string
      redirect_to?: string
    }
    type?: string
  }): Promise<AuthResult>

  // ==================== Password Management ====================
  
  /**
   * Reset password for email
   */
  resetPasswordForEmail(email: string, options?: {
    captchaToken?: string
    redirect_to?: string
  }): Promise<{ messageId?: string; [key: string]: any }>

  /**
   * Update password
   */
  updatePassword(params: {
    password: string
    nonce?: string
  }): Promise<Record<string, any>>

  // ==================== Email Management ====================
  
  /**
   * Update email
   */
  updateEmail(params: { email: string }): Promise<{ success?: boolean; [key: string]: any }>

  /**
   * Verify email change
   */
  verifyEmailChange(params: {
    email?: string
    phone?: string
    token: string
    options?: {
      captchaToken?: string
      redirect_to?: string
    }
    type?: string
  }): Promise<{ success?: boolean; [key: string]: any }>

  // ==================== Phone Management ====================
  
  /**
   * Update phone
   */
  updatePhone(params: { phone: string }): Promise<{ success?: boolean; [key: string]: any }>

  /**
   * Verify phone change
   */
  verifyPhoneChange(params: {
    email?: string
    phone?: string
    token: string
    options?: {
      captchaToken?: string
      redirect_to?: string
    }
    type?: string
  }): Promise<{ success?: boolean; [key: string]: any }>

  // ==================== Email Verification ====================
  
  /**
   * Confirm email with token
   */
  confirmEmail(token: string): Promise<void>

  // ==================== Session Management ====================
  
  /**
   * Get current session
   */
  getSession(): Session | null

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean

  /**
   * Get current user
   */
  getUser(): Promise<{ user: User | null; error?: any }>

  /**
   * Get all sessions
   */
  getSessions(): Promise<{
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
  }>

  // ==================== MFA Management ====================
  
  /**
   * List MFA factors
   */
  listMFAFactors(): Promise<{
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
  }>

  /**
   * Enroll MFA factor
   */
  enrollMFAFactor(params: {
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
  }>

  /**
   * Verify MFA factor
   */
  verifyMFAFactor(params: {
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
  }>

  /**
   * Unenroll MFA factor
   */
  unenrollMFAFactor(factorId: string): Promise<{ id?: string; [key: string]: any }>

  // ==================== Session Management (Extended) ====================
  
  /**
   * Revoke a specific session
   */
  revokeSession(sessionId: string): Promise<{ success?: boolean; [key: string]: any }>

  /**
   * Revoke all sessions (except current if excludeCurrent is true)
   */
  revokeAllSessions(excludeCurrent?: boolean): Promise<{ success?: boolean; [key: string]: any }>

  // ==================== User Management ====================
  
  /**
   * Update user profile
   */
  updateUser(params: {
    email?: string
    phone?: string
    password?: string
    user_metadata?: Record<string, any>
    [key: string]: any
  }): Promise<{ user: User | null; error?: any }>

  /**
   * Resend verification code
   */
  resend(params: {
    email?: string
    phone?: string
    type?: string
    options?: {
      captchaToken?: string
      emailRedirectTo?: string
    }
  }): Promise<{ messageId?: string; [key: string]: any }>

  // ==================== Security & Audit ====================
  
  /**
   * Get audit log
   */
  getAuditLog(): Promise<{
    events?: Array<Record<string, any>>
    [key: string]: any
  }>

  /**
   * Get devices
   */
  getDevices(): Promise<{
    devices?: Array<Record<string, any>>
    [key: string]: any
  }>
}
