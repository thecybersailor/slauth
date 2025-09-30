/** Generate a random UUID v4 */
export function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

/** Check if running in browser environment */
export function isBrowser(): boolean {
  return typeof window !== 'undefined'
}

/** Check if localStorage is supported */
export function supportsLocalStorage(): boolean {
  if (!isBrowser()) return false
  
  try {
    const key = '__aira_auth_test__'
    localStorage.setItem(key, 'test')
    localStorage.removeItem(key)
    return true
  } catch {
    return false
  }
}

/** Get item from storage asynchronously */
export async function getItemAsync(storage: Storage, key: string): Promise<string | null> {
  return new Promise((resolve) => {
    try {
      const value = storage.getItem(key)
      resolve(value)
    } catch {
      resolve(null)
    }
  })
}

/** Set item in storage asynchronously */
export async function setItemAsync(storage: Storage, key: string, value: string): Promise<void> {
  return new Promise((resolve) => {
    try {
      storage.setItem(key, value)
      resolve()
    } catch {
      resolve()
    }
  })
}

/** Remove item from storage asynchronously */
export async function removeItemAsync(storage: Storage, key: string): Promise<void> {
  return new Promise((resolve) => {
    try {
      storage.removeItem(key)
      resolve()
    } catch {
      resolve()
    }
  })
}

/** Parse URL parameters */
export function parseParametersFromURL(href: string): { [key: string]: string } {
  const url = new URL(href)
  const params: { [key: string]: string } = {}
  
  url.searchParams.forEach((value, key) => {
    params[key] = value
  })
  
  return params
}

/** Decode JWT token (without verification) */
export function decodeJWT(token: string): any {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format')
    }
    
    const payload = parts[1]
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    return JSON.parse(decoded)
  } catch {
    return null
  }
}

/** Validate JWT expiration */
export function validateExp(exp: number): boolean {
  const now = Math.floor(Date.now() / 1000)
  return exp > now
}

/** Sleep for specified milliseconds */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/** Retry function with exponential backoff */
export async function retryable<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000
): Promise<T> {
  let lastError: Error
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error as Error
      
      if (attempt === maxRetries) {
        throw lastError
      }
      
      const delay = baseDelay * Math.pow(2, attempt)
      await sleep(delay)
    }
  }
  
  throw lastError!
}

/** Convert snake_case to camelCase */
export function toCamelCase(str: string): string {
  return str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
}

/** Convert camelCase to snake_case */
export function toSnakeCase(str: string): string {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`)
}

/** Deep clone object */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }
  
  if (obj instanceof Date) {
    return new Date(obj.getTime()) as any
  }
  
  if (obj instanceof Array) {
    return obj.map(item => deepClone(item)) as any
  }
  
  if (typeof obj === 'object') {
    const cloned: any = {}
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        cloned[key] = deepClone(obj[key])
      }
    }
    return cloned
  }
  
  return obj
}

/** Check if value is empty */
export function isEmpty(value: any): boolean {
  if (value === null || value === undefined) return true
  if (typeof value === 'string') return value.trim() === ''
  if (Array.isArray(value)) return value.length === 0
  if (typeof value === 'object') return Object.keys(value).length === 0
  return false
}

/** Validate email format */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/** Validate phone format (basic) */
export function isValidPhone(phone: string): boolean {
  const phoneRegex = /^\+?[\d\s\-\(\)]+$/
  return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10
}

/** Format error message */
export function formatErrorMessage(error: any): string {
  if (typeof error === 'string') return error
  if (error?.message) return error.message
  if (error?.error?.message) return error.error.message
  return 'An unknown error occurred'
}

/** Get current timestamp in seconds */
export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000)
}

/** Check if timestamp is expired */
export function isExpired(timestamp: number, bufferSeconds: number = 60): boolean {
  const now = getCurrentTimestamp()
  return timestamp <= (now + bufferSeconds)
}
