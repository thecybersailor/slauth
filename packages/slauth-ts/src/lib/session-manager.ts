import { createValidatedHttpClient, ValidatedApiClient } from './validated-client'
import { StorageManager, SupportedStorage } from './storage'
import { AuthError } from './errors'
import { debugLog } from './helpers'
import { withBestEffortExclusiveLock } from './locks'
import * as Schemas from '../schemas/auth-api.schemas'
import * as Types from '../types/auth-api'

type TokenConsumer = (token: string | null) => void

export interface SessionManagerConfig {
  apiKey?: string | undefined
  authBaseURL?: string | undefined
  autoRefreshToken?: boolean | undefined
  crossTabRefreshLock?: boolean | undefined
  debug?: boolean | undefined
  headers?: { [key: string]: string } | undefined
  onSessionRefreshed?: ((session: Types.Session) => void) | undefined
  persistSession?: boolean | undefined
  refreshLockKey?: string | undefined
  storage?: SupportedStorage | undefined
  storageKey?: string | undefined
  timeout?: number | undefined
}

export class SessionManager {
  private readonly storage: StorageManager
  private readonly authBaseURL: string | null
  private readonly autoRefreshToken: boolean
  private readonly persistSession: boolean
  private readonly debug: boolean
  private readonly crossTabRefreshLockEnabled: boolean
  private readonly refreshLockKey: string
  private readonly onSessionRefreshed: ((session: Types.Session) => void) | undefined
  private refreshApi: ValidatedApiClient | null
  private readonly tokenConsumers = new Set<TokenConsumer>()
  private currentSession: Types.Session | null = null
  private initializationPromise: Promise<void> | null = null
  private refreshInFlight: Promise<Types.Session | null> | null = null

  constructor(config: SessionManagerConfig) {
    this.storage = new StorageManager(config.storage, config.storageKey, config.debug)
    this.authBaseURL = config.authBaseURL ?? null
    this.autoRefreshToken = config.autoRefreshToken !== false
    this.persistSession = config.persistSession !== false
    this.debug = config.debug || false
    this.crossTabRefreshLockEnabled =
      this.persistSession && this.autoRefreshToken && config.crossTabRefreshLock !== false
    this.refreshLockKey =
      config.refreshLockKey ||
      `slauth:refresh:${config.storageKey || 'aira.auth.token'}:${this.authBaseURL || 'no-auth-base-url'}`
    this.onSessionRefreshed = config.onSessionRefreshed
    this.refreshApi = this.authBaseURL
      ? createValidatedHttpClient({
          baseURL: this.authBaseURL,
          apiKey: config.apiKey,
          headers: config.headers,
          timeout: config.timeout,
          debug: config.debug
        })
      : null
  }

  registerTokenConsumer(consumer: TokenConsumer): () => void {
    this.tokenConsumers.add(consumer)
    consumer(this.currentSession?.access_token ?? null)
    return () => {
      this.tokenConsumers.delete(consumer)
    }
  }

  bindRefreshClient(client: ValidatedApiClient): void {
    this.refreshApi = client
  }

  async initialize(): Promise<void> {
    if (!this.initializationPromise) {
      this.initializationPromise = this.initializeInternal()
    }
    await this.initializationPromise
  }

  async getSession(): Promise<Types.Session | null> {
    await this.initialize()
    return this.currentSession
  }

  async getAccessToken(): Promise<string | null> {
    return (await this.getSession())?.access_token ?? null
  }

  async getUser(): Promise<Types.User | null> {
    return (await this.getSession())?.user ?? null
  }

  async hasSession(): Promise<boolean> {
    return (await this.getSession()) !== null
  }

  async setSession(session: Types.Session | null): Promise<void> {
    await this.initialize()
    if (!session) {
      await this.clearSession()
      return
    }
    await this.applySession(session, { persist: this.persistSession })
  }

  async clearSession(): Promise<void> {
    this.currentSession = null
    this.broadcastToken(null)

    if (this.persistSession) {
      await this.storage.removeSession()
      await this.storage.removeUser()
    }
  }

  async refreshSession(): Promise<Types.Session | null> {
    await this.initialize()
    return this.refreshSessionInternal()
  }

  private async initializeInternal(): Promise<void> {
    debugLog(this.debug, '[slauth:SessionManager] initialize called', {
      persistSession: this.persistSession,
      autoRefreshToken: this.autoRefreshToken
    })

    if (!this.persistSession) {
      return
    }

    const session = await this.storage.loadSession()
    if (!session) {
      return
    }

    if (this.isExpired(session)) {
      if (this.autoRefreshToken && session.refresh_token) {
        const refreshed = await this.refreshSessionInternal(session)
        if (!refreshed) {
          await this.clearSession()
        }
        return
      }

      await this.clearSession()
      return
    }

    await this.applySession(session, { persist: false })
  }

  private isExpired(session: Types.Session): boolean {
    return !!session.expires_at && session.expires_at <= Math.floor(Date.now() / 1000)
  }

  private async applySession(
    session: Types.Session,
    options: { persist: boolean }
  ): Promise<Types.Session> {
    if (!session.access_token) {
      throw new Error('No access token in session')
    }

    this.currentSession = { ...session }
    this.broadcastToken(session.access_token)

    if (this.persistSession && options.persist) {
      await this.storage.saveSession(this.currentSession)
      await this.storage.saveUser(this.currentSession.user)
    }

    return this.currentSession
  }

  private broadcastToken(token: string | null): void {
    for (const consumer of this.tokenConsumers) {
      consumer(token)
    }
  }

  private async refreshSessionInternal(seedSession?: Types.Session | null): Promise<Types.Session | null> {
    if (this.refreshInFlight) {
      return this.refreshInFlight
    }

    this.refreshInFlight = (async () => {
      const refreshImpl = async (): Promise<Types.Session | null> => {
        const latestSession = this.persistSession ? await this.storage.loadSession() : null
        const latestNotExpired = latestSession && !this.isExpired(latestSession as Types.Session)
        const latestChanged =
          !!latestSession &&
          (!!latestSession.access_token && latestSession.access_token !== this.currentSession?.access_token ||
            !!latestSession.refresh_token && latestSession.refresh_token !== this.currentSession?.refresh_token)

        if (latestNotExpired && latestChanged) {
          const adopted = await this.applySession(latestSession as Types.Session, { persist: false })
          this.onSessionRefreshed?.(adopted)
          return adopted
        }

        const sessionToRefresh = (latestSession as Types.Session | null) ?? seedSession ?? this.currentSession
        if (!sessionToRefresh?.refresh_token || !this.refreshApi) {
          return null
        }

        const { data, error } = await this.refreshApi.postWithValidation<Types.AuthData>(
          '/token?grant_type=refresh_token',
          { refresh_token: sessionToRefresh.refresh_token },
          Schemas.RefreshTokenRequestSchema,
          Schemas.AuthDataSchema,
          { _skipAutoRefresh: true } as any
        )

        if (error || !data?.session) {
          return null
        }

        const refreshed = await this.applySession(data.session as Types.Session, { persist: this.persistSession })
        this.onSessionRefreshed?.(refreshed)
        return refreshed
      }

      if (!this.crossTabRefreshLockEnabled) {
        return refreshImpl()
      }

      return withBestEffortExclusiveLock(this.refreshLockKey, refreshImpl)
    })()

    try {
      return await this.refreshInFlight
    } finally {
      this.refreshInFlight = null
    }
  }
}
