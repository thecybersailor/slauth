import { createHttpClient } from './lib/fetch'
import { Session } from './lib/types'
import { ValidatedApiClient } from './lib/validated-client'
import * as Types from './types/admin-api'
import * as Schemas from './schemas/admin-api.schemas'

/** Admin API client - handles administrative operations */
export class AdminApi {
  private api: ValidatedApiClient
  private currentSession: Session | null = null

  constructor(baseURL: string, config: any) {
    this.api = new ValidatedApiClient({
      baseURL,
      ...config
    })
  }

  /**
   * Set session for admin operations (typically from authClient)
   * IMPORTANT: This stores a reference to the session object, not a copy.
   * When called with authClient.getSession(), both clients will share the same
   * session object. This enables automatic synchronization - when authClient
   * refreshes the token, the changes propagate automatically to adminClient
   * because AuthApi.setSession() uses Object.assign() to update the same object.
   * 
   * Usage: adminClient.setSession(authClient.getSession())
   */
  setSession(session: Session): void {
    this.currentSession = session
    this.api.setAuth(session.access_token || null)
  }

  /** Clear current session */
  clearSession(): void {
    this.currentSession = null
    this.api.setAuth(null)
  }

  /** Get current access token */
  getToken(): string | null {
    return this.currentSession?.access_token || null
  }

  /** Check if admin client is authenticated */
  isAuthenticated(): boolean {
    return this.currentSession !== null
  }

  /** Get current session */
  getSession(): Session | null {
    return this.currentSession
  }

  // SAML SSO Management
  async createSAMLProvider(provider: Types.CreateSAMLProviderRequest): Promise<Types.SAMLProviderResponse> {
    const { data, error } = await this.api.postWithValidation<Types.SAMLProviderResponse>(
      '/saml/providers',
      provider,
      Schemas.CreateSAMLProviderRequestSchema,
      Schemas.SAMLProviderResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async listSAMLProviders(): Promise<Types.ListSAMLProvidersResponse> {
    const { data, error } = await this.api.getWithValidation<Types.ListSAMLProvidersResponse>(
      '/saml/providers',
      Schemas.ListSAMLProvidersResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async getSAMLProvider(id: string): Promise<Types.SAMLProviderResponse> {
    const { data, error } = await this.api.getWithValidation<Types.SAMLProviderResponse>(
      `/saml/providers/${id}`,
      Schemas.SAMLProviderResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async updateSAMLProvider(id: string, provider: Types.UpdateSAMLProviderRequest): Promise<Types.SAMLProviderResponse> {
    const { data, error } = await this.api.putWithValidation<Types.SAMLProviderResponse>(
      `/saml/providers/${id}`,
      provider,
      Schemas.UpdateSAMLProviderRequestSchema,
      Schemas.SAMLProviderResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async deleteSAMLProvider(id: string): Promise<void> {
    const { error } = await this.api.delete(`/saml/providers/${id}`)

    if (error) {
      return Promise.reject(error)
    }
  }

  async testSAMLProvider(id: string): Promise<void> {
    const { error } = await this.api.post(`/saml/providers/${id}/test`, {})

    if (error) {
      return Promise.reject(error)
    }
  }

  // User Management
  
  /**
   * Query users with filters, sorting, and pagination
   * @param params Query parameters (filters, sort, pagination)
   */
  async queryUsers(params?: {
    filters?: Record<string, any>
    sort?: string[]
    pagination?: {
      page?: number
      pageSize?: number
    }
  }): Promise<Types.ListUsersResponse> {
    const { data, error } = await this.api.post('/users/query', params || {})

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  /**
   * @deprecated Use queryUsers() instead
   * List all users (simple query without filters)
   */
  async listUsers(): Promise<Types.ListUsersResponse> {
    return this.queryUsers({})
  }

  async getUser(id: string): Promise<Types.AdminUserResponse> {
    const { data, error } = await this.api.getWithValidation<Types.AdminUserResponse>(
      `/users/${id}`,
      Schemas.AdminUserResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async updateUser(id: string, updates: Types.AdminUpdateUserRequest): Promise<Types.AdminUserResponse> {
    const { data, error } = await this.api.putWithValidation<Types.AdminUserResponse>(
      `/users/${id}`,
      updates,
      Schemas.AdminUpdateUserRequestSchema,
      Schemas.AdminUserResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async deleteUser(id: string): Promise<void> {
    const { error } = await this.api.delete(`/users/${id}`)

    if (error) {
      return Promise.reject(error)
    }
  }

  async createUser(userData: Types.AdminCreateUserRequest): Promise<Types.AdminUserResponse> {
    const { data, error } = await this.api.postWithValidation<Types.AdminUserResponse>(
      '/users',
      userData,
      Schemas.AdminCreateUserRequestSchema,
      Schemas.AdminUserResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async resetUserPassword(userId: string, passwordData: Types.AdminResetPasswordRequest): Promise<void> {
    const { error } = await this.api.postWithValidation(
      `/users/${userId}/reset-password`,
      passwordData,
      Schemas.AdminResetPasswordRequestSchema
    )

    if (error) {
      return Promise.reject(error)
    }
  }

  async setUserEmailConfirmed(userId: string, confirmed: boolean): Promise<void> {
    const { error } = await this.api.put(`/users/${userId}/email-confirmed`, { confirmed })

    if (error) {
      return Promise.reject(error)
    }
  }

  async setUserPhoneConfirmed(userId: string, confirmed: boolean): Promise<void> {
    const { error } = await this.api.put(`/users/${userId}/phone-confirmed`, { confirmed })

    if (error) {
      return Promise.reject(error)
    }
  }

  // Session Management
  async listAllSessions(): Promise<Types.ListSessionsResponse> {
    const { data, error } = await this.api.getWithValidation<Types.ListSessionsResponse>(
      '/sessions',
      Schemas.ListSessionsResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async listUserSessions(userId: string): Promise<Types.ListSessionsResponse> {
    const { data, error } = await this.api.getWithValidation<Types.ListSessionsResponse>(
      `/users/${userId}/sessions`,
      Schemas.ListSessionsResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async revokeSession(sessionId: string): Promise<void> {
    const { error } = await this.api.delete(`/sessions/${sessionId}`)

    if (error) {
      return Promise.reject(error)
    }
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    const { error } = await this.api.delete(`/users/${userId}/sessions`)

    if (error) {
      return Promise.reject(error)
    }
  }

  // Identity Management
  async listUserIdentities(userId: string): Promise<any> {
    const { data, error } = await this.api.get(`/users/${userId}/identities`)

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async deleteUserIdentity(userId: string, identityId: string): Promise<void> {
    const { error } = await this.api.delete(`/users/${userId}/identities/${identityId}`)

    if (error) {
      return Promise.reject(error)
    }
  }

  // System Stats
  async getUserCount(): Promise<Types.StatsResponse> {
    const { data, error } = await this.api.getWithValidation<Types.StatsResponse>(
      '/stats/users',
      Schemas.StatsResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async getActiveSessionCount(): Promise<Types.SessionStatsResponse> {
    const { data, error } = await this.api.getWithValidation<Types.SessionStatsResponse>(
      '/stats/sessions',
      Schemas.SessionStatsResponseSchema
    )

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async getRecentSignups(): Promise<any> {
    const { data, error } = await this.api.get('/stats/recent-signups')

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  async getRecentSignins(): Promise<any> {
    const { data, error } = await this.api.get('/stats/recent-signins')

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  /**
   * Get instance configuration
   */
  async getInstanceConfig() {
    const { data, error } = await this.api.get('/config')

    if (error) {
      return Promise.reject(error)
    }

    return data
  }

  /**
   * Update instance configuration
   */
  async updateInstanceConfig(config: any) {
    const { data, error } = await this.api.put('/config', {
      config,
    })

    if (error) {
      return Promise.reject(error)
    }

    return data
  }
}
