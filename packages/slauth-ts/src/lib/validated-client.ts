import { HttpClient, HttpClientConfig } from './fetch'
import { AuthError } from './errors'
import { z } from 'zod'

/** Response wrapper for validated API calls */
export interface FetchResponse<T = any> {
  data: T | null
  error: AuthError | null
}

export class ValidatedApiClient extends HttpClient {
  constructor(config: HttpClientConfig) {
    super(config)
  }

  /** Override get to return FetchResponse */
  // @ts-expect-error - Intentionally changing return type from AxiosResponse to FetchResponse
  async get<T>(url: string, options: any = {}): Promise<FetchResponse<T>> {
    const response = await super.get<T>(url, options).catch(() => null)
    
    if (!response) {
      return { data: null, error: { message: 'Request failed', key: 'request_failed' } }
    }
    
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return { data: null, error: errorData }
      }
    }
    
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    return { data: actualData as T, error: null }
  }

  /** Override post to return FetchResponse */
  // @ts-expect-error - Intentionally changing return type from AxiosResponse to FetchResponse
  async post<T>(url: string, body?: any, options: any = {}): Promise<FetchResponse<T>> {
    const response = await super.post<T>(url, body, options).catch(() => null)
    
    if (!response) {
      return { data: null, error: { message: 'Request failed', key: 'request_failed' } }
    }
    
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return { data: null, error: errorData }
      }
    }
    
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    return { data: actualData as T, error: null }
  }

  /** Override put to return FetchResponse */
  // @ts-expect-error - Intentionally changing return type from AxiosResponse to FetchResponse
  async put<T>(url: string, body?: any, options: any = {}): Promise<FetchResponse<T>> {
    const response = await super.put<T>(url, body, options).catch(() => null)
    
    if (!response) {
      return { data: null, error: { message: 'Request failed', key: 'request_failed' } }
    }
    
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return { data: null, error: errorData }
      }
    }
    
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    return { data: actualData as T, error: null }
  }

  /** Override patch to return FetchResponse */
  // @ts-expect-error - Intentionally changing return type from AxiosResponse to FetchResponse
  async patch<T>(url: string, body?: any, options: any = {}): Promise<FetchResponse<T>> {
    const response = await super.patch<T>(url, body, options).catch(() => null)
    
    if (!response) {
      return { data: null, error: { message: 'Request failed', key: 'request_failed' } }
    }
    
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return { data: null, error: errorData }
      }
    }
    
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    return { data: actualData as T, error: null }
  }

  /** Override delete to return FetchResponse */
  // @ts-expect-error - Intentionally changing return type from AxiosResponse to FetchResponse
  async delete<T>(url: string, options: any = {}): Promise<FetchResponse<T>> {
    const response = await super.delete<T>(url, options).catch(() => null)
    
    if (!response) {
      return { data: null, error: { message: 'Request failed', key: 'request_failed' } }
    }
    
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return { data: null, error: errorData }
      }
    }
    
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    return { data: actualData as T, error: null }
  }

  async postWithValidation<T>(
    url: string, 
    body: any,
    requestSchema?: z.ZodSchema,
    responseSchema?: z.ZodSchema
  ): Promise<FetchResponse<T>> {
    
    // 1. Validate request body
    if (requestSchema && body) {
      const validation = requestSchema.safeParse(body)
      if (!validation.success) {
        return {
          data: null,
          error: {
            message: validation.error.issues[0].message,
            key: 'validation_error'
          }
        }
      }
    }
    
    // 2. Call HttpClient and catch HTTP errors
    const response = await super.post<T>(url, body).catch(() => null)
    
    if (!response) {
      return {
        data: null,
        error: {
          message: 'Request failed',
          key: 'request_failed'
        }
      }
    }
    
    // 3. Check for business errors in response
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return {
          data: null,
          error: errorData
        }
      }
    }
    
    // 4. Extract data from Pin framework format
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    // 5. Validate response
    if (responseSchema && actualData) {
      const validation = responseSchema.safeParse(actualData)
      if (!validation.success) {
        console.error('Response validation failed:', {
          data: actualData,
          errors: validation.error.issues
        })
        return {
          data: null,
          error: {
            message: `Invalid response format: ${validation.error.issues[0]?.message}`,
            key: 'response_validation_error'
          }
        }
      }
    }
    
    return {
      data: actualData as T,
      error: null
    }
  }

  async getWithValidation<T>(
    url: string,
    responseSchema?: z.ZodSchema
  ): Promise<FetchResponse<T>> {
    
    // 1. Call HttpClient and catch HTTP errors
    const response = await super.get<T>(url).catch(() => null)
    
    if (!response) {
      return {
        data: null,
        error: {
          message: 'Request failed',
          key: 'request_failed'
        }
      }
    }
    
    // 2. Check for business errors in response
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return {
          data: null,
          error: errorData
        }
      }
    }
    
    // 3. Extract data from Pin framework format
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    // 4. Validate response
    if (responseSchema && actualData) {
      const validation = responseSchema.safeParse(actualData)
      if (!validation.success) {
        return {
          data: null,
          error: {
            message: 'Invalid response format',
            key: 'response_validation_error'
          }
        }
      }
    }
    
    return {
      data: actualData as T,
      error: null
    }
  }

  async putWithValidation<T>(
    url: string,
    body: any,
    requestSchema?: z.ZodSchema,
    responseSchema?: z.ZodSchema
  ): Promise<FetchResponse<T>> {
    
    // 1. Validate request body
    if (requestSchema && body) {
      const validation = requestSchema.safeParse(body)
      if (!validation.success) {
        return {
          data: null,
          error: {
            message: validation.error.issues[0].message,
            key: 'validation_error'
          }
        }
      }
    }
    
    // 2. Call HttpClient and catch HTTP errors
    const response = await super.put<T>(url, body).catch(() => null)
    
    if (!response) {
      return {
        data: null,
        error: {
          message: 'Request failed',
          key: 'request_failed'
        }
      }
    }
    
    // 3. Check for business errors in response
    if (response.data && typeof response.data === 'object' && 'error' in response.data) {
      const errorData = (response.data as any).error
      if (errorData && errorData !== null) {
        return {
          data: null,
          error: errorData
        }
      }
    }
    
    // 4. Extract data from Pin framework format
    const actualData = response.data && typeof response.data === 'object' && 'data' in response.data
      ? (response.data as any).data
      : response.data
    
    // 5. Validate response
    if (responseSchema && actualData) {
      const validation = responseSchema.safeParse(actualData)
      if (!validation.success) {
        return {
          data: null,
          error: {
            message: 'Invalid response format',
            key: 'response_validation_error'
          }
        }
      }
    }
    
    return {
      data: actualData as T,
      error: null
    }
  }
}

export function createValidatedHttpClient(config: HttpClientConfig): ValidatedApiClient {
  return new ValidatedApiClient(config)
}
