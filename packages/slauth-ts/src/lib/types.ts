import type { AuthError } from './errors'
import type { Session, User } from '../types/auth-api'
import type { AdminUserResponse } from '../types/admin-api'

// Re-export AuthError for convenience
export type { AuthError }

// Re-export Session type for convenience
export type { Session }

// Re-export User type for convenience
export type { User }

// Re-export AdminUserResponse for convenience
export type { AdminUserResponse }


/** Authentication change events */
export type AuthChangeEvent =
  | 'INITIAL_SESSION'
  | 'SIGNED_IN'
  | 'SIGNED_OUT'
  | 'TOKEN_REFRESHED'
  | 'USER_UPDATED'
  | 'PASSWORD_RECOVERY'
  | 'MFA_CHALLENGE_VERIFIED'
  | 'AUTH_ID_TOKEN'
  | 'AUTH_PKCE'

/** Service configuration */
export interface ServiceConfig {
  /** Complete URL for the service */
  url: string
}

/** Client configuration options */
export interface ClientsConfig {
  /** Auth service configuration */
  auth?: ServiceConfig
  /** Admin service configuration */
  admin?: ServiceConfig
  /** API key for authentication */
  apiKey?: string
  /** Additional headers to send with requests */
  headers?: { [key: string]: string }
  /** Auto refresh tokens before expiry */
  autoRefreshToken?: boolean
  /** Persist session in local storage */
  persistSession?: boolean
  /** Storage implementation for session persistence */
  storage?: Storage
  /** Storage key for session persistence */
  storageKey?: string
  /** Coordinate refresh across tabs/pages (uses navigator.locks when available). Defaults to enabled when persistSession+autoRefreshToken are enabled; set false to opt out. */
  crossTabRefreshLock?: boolean
  /** Optional lock name override; default is derived from storageKey */
  refreshLockKey?: string
  /** Debug mode */
  debug?: boolean
  /** Request timeout */
  timeout?: number
  /** Callback when 401 unauthorized error occurs or refresh fails */
  onUnauthorized?: () => void
  /** Callback when session is refreshed successfully */
  onSessionRefreshed?: (session: Session) => void
  /** Callback for general auth errors */
  onAuthError?: (error: AuthError) => void
}
