import { AuthApi } from './AuthApi'
import { AdminApi } from './AdminApi'
import { ClientsConfig } from './lib/types'
import { SessionManager } from './lib/session-manager'

/** Create all API clients */
export function createClients(config: ClientsConfig) {
  const sessionManager = new SessionManager({
    authBaseURL: config.auth?.url,
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

  // Extract shared config
  const sharedConfig = {
    apiKey: config.apiKey,
    authBaseURL: config.auth?.url,
    headers: config.headers,
    autoRefreshToken: config.autoRefreshToken,
    persistSession: config.persistSession,
    storage: config.storage,
    storageKey: config.storageKey,
    crossTabRefreshLock: config.crossTabRefreshLock,
    refreshLockKey: config.refreshLockKey,
    debug: config.debug,
    timeout: config.timeout,
    // Pass callbacks
    onUnauthorized: config.onUnauthorized,
    onSessionRefreshed: config.onSessionRefreshed,
    onAuthError: config.onAuthError
  }
  
  // Create clients only if config is provided
  const authClient = config.auth 
    ? new AuthApi(config.auth.url, sharedConfig, sessionManager)
    : null
  
  const adminClient = config.admin
    ? new AdminApi(config.admin.url, sharedConfig, sessionManager)
    : null

  return {
    authClient,
    adminClient,
    sessionManager
  }
}

// Export the API classes for direct use
export { AuthApi } from './AuthApi'
export { AdminApi } from './AdminApi'
