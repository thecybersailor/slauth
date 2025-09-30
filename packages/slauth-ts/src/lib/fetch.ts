import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios'
import { 
  AuthError, 
  AuthNetworkError,
  isAuthError
} from './errors'
import { version } from './version'

/** HTTP client configuration */
export interface HttpClientConfig {
  baseURL: string
  apiKey?: string
  headers?: { [key: string]: string }
  timeout?: number
  debug?: boolean
  /** Callback when 401 unauthorized error occurs */
  onUnauthorized?: () => void
  /** Callback when session expires */
  onSessionExpired?: () => void
  /** Callback for general auth errors */
  onAuthError?: (error: AuthError) => void
}

/** Request options */
export interface RequestOptions {
  headers?: { [key: string]: string }
  noResolveJson?: boolean
  redirectTo?: string
  body?: any
}

/** Response wrapper */
export interface FetchResponse<T = any> {
  data: T
  error: AuthError | null
}

/** HTTP client for slauth API */
export class HttpClient {
  private client: AxiosInstance
  private debug: boolean
  protected config: HttpClientConfig

  constructor(config: HttpClientConfig) {
    this.config = config
    this.debug = config.debug || false
    
    this.client = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout || 10000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `@cybersailor/slauth-ts-js/${version}`,
        ...config.headers,
        ...(config.apiKey && { 'Authorization': `Bearer ${config.apiKey}` })
      }
    })

    // Setup interceptors
    this.setupInterceptors()
  }

  /** Setup interceptors */
  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        if (this.debug) {
          console.log(`[slauth] ${config.method?.toUpperCase()} ${config.url}`, {
            headers: config.headers,
            data: config.data
          })
        }
        return config
      },
      (error) => {
        if (this.debug) {
          console.error('[slauth] Request error:', error)
        }
        return Promise.reject(error)
      }
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        if (this.debug) {
          console.log(`[slauth] Response ${response.status}:`, response.data)
        }
        return response
      },
      (error) => {
        if (this.debug) {
          console.error('[slauth] Response error:', error)
        }
        const authError = this.handleError(error)
        
        // Trigger error callbacks based on error type (only for AuthError, not AuthNetworkError)
        if (isAuthError(authError)) {
          if (authError.key === 'auth.authorization_required' || 
              authError.key === 'auth.unauthorized') {
            this.config.onUnauthorized?.()
          } else if (authError.key === 'auth.session_expired') {
            this.config.onSessionExpired?.()
          }
          
          // Trigger general error callback
          this.config.onAuthError?.(authError)
        }
        
        return Promise.reject(authError)
      }
    )
  }

  /** Set authorization header */
  setAuth(token: string | null) {
    if (token) {
      this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`
    } else {
      delete this.client.defaults.headers.common['Authorization']
    }
  }

  /** Make a GET request */
  async get<T = any>(url: string, options: RequestOptions = {}): Promise<FetchResponse<T>> {
    try {
      const response = await this.client.get<T>(url, {
        ...(options.headers && { headers: options.headers })
      })

      // Check if response contains error field (backend returns { data, error } format)
      if (response.data && typeof response.data === 'object' && 'error' in response.data) {
        const errorData = (response.data as any).error
        if (errorData && errorData !== null) {
          return { data: null as any, error: errorData }
        }
      }

      // Extract the actual data from the Pin framework response format
      const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
        ? (response.data as any).data
        : response.data

      return { data: actualData as T, error: null }
    } catch (error) {
      return { data: null as any, error: this.handleError(error) }
    }
  }

  /** Make a POST request */
  async post<T = any>(url: string, body?: any, options: RequestOptions = {}): Promise<FetchResponse<T>> {
    try {
      const response = await this.client.post<T>(url, body, {
        ...(options.headers && { headers: options.headers })
      })

      // Debug: Log the actual response data
      if (this.debug) {
        console.log('[slauth] POST Response data:', JSON.stringify(response.data, null, 2))
      }

      // Check if response contains error field (backend returns { data, error } format)
      if (response.data && typeof response.data === 'object' && 'error' in response.data) {
        const errorData = (response.data as any).error
        if (errorData && errorData !== null) {
          if (this.debug) {
            console.log('[slauth] Error detected in response:', errorData)
          }
          const authError: AuthError = {
            message: errorData.message || 'Authentication failed',
            key: errorData.code || errorData.key || 'auth_error',
            type: errorData.type
          }
          return { data: null as any, error: authError }
        }
      }

      // Extract the actual data from the Pin framework response format
      const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
        ? (response.data as any).data
        : response.data

      return { data: actualData as T, error: null }
    } catch (error) {
      return { data: null as any, error: this.handleError(error) }
    }
  }

  /** Make a PUT request */
  async put<T = any>(url: string, body?: any, options: RequestOptions = {}): Promise<FetchResponse<T>> {
    try {
      const response = await this.client.put<T>(url, body, {
        ...(options.headers && { headers: options.headers })
      })

      // Check if response contains error field (backend returns { data, error } format)
      if (response.data && typeof response.data === 'object' && 'error' in response.data) {
        const errorData = (response.data as any).error
        if (errorData && errorData !== null) {
          return { data: null as any, error: errorData }
        }
      }

      // Extract the actual data from the Pin framework response format
      const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
        ? (response.data as any).data
        : response.data

      return { data: actualData as T, error: null }
    } catch (error) {
      return { data: null as any, error: this.handleError(error) }
    }
  }

  /** Make a PATCH request */
  async patch<T = any>(url: string, body?: any, options: RequestOptions = {}): Promise<FetchResponse<T>> {
    try {
      const response = await this.client.patch<T>(url, body, {
        ...(options.headers && { headers: options.headers })
      })

      // Check if response contains error field (backend returns { data, error } format)
      if (response.data && typeof response.data === 'object' && 'error' in response.data) {
        const errorData = (response.data as any).error
        if (errorData && errorData !== null) {
          return { data: null as any, error: errorData }
        }
      }

      // Extract the actual data from the Pin framework response format
      const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
        ? (response.data as any).data
        : response.data

      return { data: actualData as T, error: null }
    } catch (error) {
      return { data: null as any, error: this.handleError(error) }
    }
  }

  /** Make a DELETE request */
  async delete<T = any>(url: string, options: RequestOptions = {}): Promise<FetchResponse<T>> {
    try {
      const response = await this.client.delete<T>(url, {
        ...(options.headers && { headers: options.headers })
      })

      // Check if response contains error field (backend returns { data, error } format)
      if (response.data && typeof response.data === 'object' && 'error' in response.data) {
        const errorData = (response.data as any).error
        if (errorData && errorData !== null) {
          return { data: null as any, error: errorData }
        }
      }

      // Extract the actual data from the Pin framework response format
      const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
        ? (response.data as any).data
        : response.data

      return { data: actualData as T, error: null }
    } catch (error) {
      return { data: null as any, error: this.handleError(error) }
    }
  }

  /** Handle axios errors and convert to AuthError */
  private handleError(error: any): AuthError | AuthNetworkError {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError
      
      // Network errors
      if (!axiosError.response) {
        return new AuthNetworkError(axiosError.message)
      }

      const { data, status } = axiosError.response
      const errorData = data as any

      // Handle 401 specifically if error data doesn't have proper key
      if (status === 401) {
        // Try to extract error from Pin framework format
        const authError = errorData?.error || errorData
        
        // Ensure it has a key field, fallback to auth.unauthorized
        if (!authError.key) {
          return {
            message: authError.message || 'Unauthorized',
            key: 'auth.unauthorized',
            type: authError.type || 'user'
          }
        }
        return authError
      }

      // Return Pin framework error directly
      return errorData?.error || errorData
    }

    // Non-axios errors
    if (isAuthError(error)) {
      return error
    }

    return new AuthNetworkError(error?.message)
  }
}

/** Create HTTP client instance */
export function createHttpClient(config: HttpClientConfig): HttpClient {
  return new HttpClient(config)
}
