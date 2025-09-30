import { HttpClient, HttpClientConfig, FetchResponse } from './fetch'
import { AuthError } from './errors'
import { z } from 'zod'

export class ValidatedApiClient extends HttpClient {
  constructor(config: HttpClientConfig) {
    super(config)
  }

  async postWithValidation<T>(
    url: string, 
    body: any,
    requestSchema?: z.ZodSchema,
    responseSchema?: z.ZodSchema
  ): Promise<FetchResponse<T>> {
    
    if (requestSchema && body) {
      const validation = requestSchema.safeParse(body)
      if (!validation.success) {
        return {
          data: null as any,
          error: {
            message: validation.error.issues[0].message,
            key: 'validation_error'
          }
        }
      }
    }
    
    
    const response = await super.post<T>(url, body)
    
    
    if (responseSchema && response.data) {
      const validation = responseSchema.safeParse(response.data)
      if (!validation.success) {
        console.error('Response validation failed:', {
          data: response.data,
          errors: validation.error.issues
        })
        return {
          data: null as any,
          error: {
            message: `Invalid response format: ${validation.error.issues[0]?.message}`,
            key: 'response_validation_error'
          }
        }
      }
    }
    
    return response
  }

  async getWithValidation<T>(
    url: string,
    responseSchema?: z.ZodSchema
  ): Promise<FetchResponse<T>> {
    
    const response = await super.get<T>(url)
    
    
    if (responseSchema && response.data) {
      const validation = responseSchema.safeParse(response.data)
      if (!validation.success) {
        return {
          data: null as any,
          error: {
            message: 'Invalid response format',
            key: 'response_validation_error'
          }
        }
      }
    }
    
    return response
  }

  async putWithValidation<T>(
    url: string,
    body: any,
    requestSchema?: z.ZodSchema,
    responseSchema?: z.ZodSchema
  ): Promise<FetchResponse<T>> {
    
    if (requestSchema && body) {
      const validation = requestSchema.safeParse(body)
      if (!validation.success) {
        return {
          data: null as any,
          error: {
            message: validation.error.issues[0].message,
            key: 'validation_error'
          }
        }
      }
    }
    
    
    const response = await super.put<T>(url, body)
    
    
    if (responseSchema && response.data) {
      const validation = responseSchema.safeParse(response.data)
      if (!validation.success) {
        return {
          data: null as any,
          error: {
            message: 'Invalid response format',
            key: 'response_validation_error'
          }
        }
      }
    }
    
    return response
  }
}

export function createValidatedHttpClient(config: HttpClientConfig): ValidatedApiClient {
  return new ValidatedApiClient(config)
}
