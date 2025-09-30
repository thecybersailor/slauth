import { ref } from 'vue'
import type { Localization } from '../types'
import { formatError, mergeLocalization } from '../localization'

/**
 */
export function useErrorHandler(localization?: Localization) {
  const error = ref<string | null>(null)
  const errorKey = ref<string | null>(null)
  const mergedLocalization = localization ? mergeLocalization(localization) : undefined

  /**
   */
  const handleError = (err: any): string => {
    const errorMessage = formatError(err, mergedLocalization)
    error.value = errorMessage
    
    errorKey.value = err?.key || null
    return errorMessage
  }

  /**
   */
  const clearError = () => {
    error.value = null
    errorKey.value = null
  }

  /**
   */
  const hasError = () => {
    return error.value !== null
  }

  return {
    error,
    errorKey,
    handleError,
    clearError,
    hasError
  }
}
