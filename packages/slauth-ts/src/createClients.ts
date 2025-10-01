import { AuthApi } from './AuthApi'
import { AdminApi } from './AdminApi'
import { ClientsConfig } from './lib/types'

/** Create all API clients */
export function createClients(config: ClientsConfig) {
  // Extract shared config
  const sharedConfig = {
    apiKey: config.apiKey,
    headers: config.headers,
    autoRefreshToken: config.autoRefreshToken,
    persistSession: config.persistSession,
    storage: config.storage,
    debug: config.debug,
    timeout: config.timeout,
    // Pass callbacks
    onUnauthorized: config.onUnauthorized,
    onSessionRefreshed: config.onSessionRefreshed,
    onAuthError: config.onAuthError
  }
  
  // Create clients
  const authClient = new AuthApi(
    config.auth.url,
    sharedConfig
  )
  
  const adminClient = new AdminApi(
    config.admin.url,
    sharedConfig
  )

  return {
    authClient,
    adminClient
  }
}

// Export the API classes for direct use
export { AuthApi } from './AuthApi'
export { AdminApi } from './AdminApi'