// Main client creation function
export { createClients } from './createClients'

// API client exports
export { AuthApi } from './AuthApi'
export { AdminApi } from './AdminApi'
export { SessionManager } from './lib/session-manager'

// Type exports
export * from './lib/types'
export * from './lib/errors'

// Namespace exports for types
export * as Types from './lib/types'

// Utility exports
export { version } from './lib/version'
