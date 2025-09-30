export interface AuthError {
  message: string
  type?: string
  key?: string
  trace_id?: string
  is_system_error?: boolean
}

export class AuthNetworkError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthNetworkError'
  }
}

/** Type guard for error checking */
export function isAuthError(error: any): error is AuthError {
  return error && typeof error.message === 'string'
}

export function isAuthNetworkError(error: any): error is AuthNetworkError {
  return error instanceof AuthNetworkError
}
