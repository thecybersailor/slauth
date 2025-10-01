import { ref, reactive } from 'vue'
import type { ViewType, FormState, FormErrors } from '../types'

/** Auth state management composable */
export function useAuthState(initialView: ViewType = 'sign_in') {
  const currentView = ref<ViewType>(initialView)
  const message = ref<string>('')
  const messageType = ref<'success' | 'error' | 'info'>('info')
  const messageKey = ref<string>('')

  // Form state
  const formState = reactive<FormState>({
    loading: false,
    errors: {},
    message: '',
    messageType: 'info',
    messageKey: ''
  })

  // View navigation
  const setView = (view: ViewType) => {
    currentView.value = view
    clearMessage()
    clearErrors()
  }

  const goToSignIn = () => setView('sign_in')
  const goToSignUp = () => setView('sign_up')
  const goToMagicLink = () => setView('magic_link')
  const goToForgotPassword = () => setView('forgotten_password')
  const goToUpdatePassword = () => setView('update_password')
  const goToVerifyOtp = () => setView('verify_otp')

  // Message management
  const setMessage = (msg: string, type: 'success' | 'error' | 'info' = 'info', key?: string) => {
    message.value = msg
    messageType.value = type
    messageKey.value = key || ''
    formState.message = msg
    formState.messageType = type
    formState.messageKey = key || ''
  }

  const clearMessage = () => {
    message.value = ''
    messageKey.value = ''
    formState.message = ''
    formState.messageKey = ''
  }

  const setSuccessMessage = (msg: string, key?: string) => setMessage(msg, 'success', key)
  const setErrorMessage = (msg: string, key?: string) => setMessage(msg, 'error', key)
  const setInfoMessage = (msg: string, key?: string) => setMessage(msg, 'info', key)

  // Error management
  const setError = (field: keyof FormErrors, error: string) => {
    formState.errors[field] = error
  }

  const setErrors = (errors: FormErrors) => {
    formState.errors = { ...errors }
  }

  const clearError = (field: keyof FormErrors) => {
    delete formState.errors[field]
  }

  const clearErrors = () => {
    formState.errors = {}
  }

  const hasError = (field: keyof FormErrors) => {
    return !!formState.errors[field]
  }

  const getError = (field: keyof FormErrors) => {
    return formState.errors[field] || ''
  }

  // Loading state
  const setLoading = (loading: boolean) => {
    formState.loading = loading
  }

  // Form validation
  const validateEmail = (email: string): string | null => {
    if (!email) return 'Email is required'
    if (email.length > 254) return 'Email is too long'
    const atIndex = email.indexOf('@')
    const lastDotIndex = email.lastIndexOf('.')
    if (atIndex === -1 || lastDotIndex === -1 || atIndex > lastDotIndex || lastDotIndex === email.length - 1) {
      return 'Please enter a valid email address'
    }
    return null
  }

  const validatePassword = (password: string, minLength = 6): string | null => {
    if (!password) return 'Password is required'
    if (password.length < minLength) {
      return `Password must be at least ${minLength} characters`
    }
    return null
  }

  const validateConfirmPassword = (password: string, confirmPassword: string): string | null => {
    if (!confirmPassword) return 'Please confirm your password'
    if (password !== confirmPassword) return 'Passwords do not match'
    return null
  }

  const validateToken = (token: string): string | null => {
    if (!token) return 'Verification code is required'
    if (token.length < 6) return 'Verification code must be at least 6 characters'
    return null
  }

  // Form validation helper
  const validateForm = (fields: Record<string, string>, rules: Record<string, (value: string) => string | null>) => {
    const errors: FormErrors = {}
    let isValid = true

    for (const [field, value] of Object.entries(fields)) {
      const rule = rules[field]
      if (rule) {
        const error = rule(value)
        if (error) {
          errors[field as keyof FormErrors] = error
          isValid = false
        }
      }
    }

    setErrors(errors)
    return isValid
  }

  // Reset all state
  const reset = () => {
    clearMessage()
    clearErrors()
    setLoading(false)
  }

  return {
    // State
    currentView,
    message,
    messageType,
    formState,

    // View navigation
    setView,
    goToSignIn,
    goToSignUp,
    goToMagicLink,
    goToForgotPassword,
    goToUpdatePassword,
    goToVerifyOtp,

    // Message management
    setMessage,
    clearMessage,
    setSuccessMessage,
    setErrorMessage,
    setInfoMessage,

    // Error management
    setError,
    setErrors,
    clearError,
    clearErrors,
    hasError,
    getError,

    // Loading state
    setLoading,

    // Validation
    validateEmail,
    validatePassword,
    validateConfirmPassword,
    validateToken,
    validateForm,

    // Reset
    reset
  }
}
