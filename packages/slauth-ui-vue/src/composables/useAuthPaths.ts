import { ref, computed } from 'vue'
import { useAuthContext } from './useAuthContext'
import { buildUrlWithPreservedParams } from '../lib/redirectManager'

export const KNOWN_ACTIONS = ['signup', 'signin', 'forgot-password', 'reset-password', 'magic-link', 'verify-otp', 'callback', 'confirm', 'confirmed']

const normalizeConfiguredBasePath = (authBaseUrl?: string): string => {
  if (!authBaseUrl) {
    return ''
  }

  try {
    return new URL(authBaseUrl, window.location.origin).pathname.replace(/\/$/, '')
  } catch {
    return authBaseUrl.replace(/\/$/, '')
  }
}

const detectAuthBasePath = (configuredBasePath = ''): { basePath: string, action: string } => {
  const currentPath = window.location.pathname
  const normalizedPath = currentPath.replace(/\/$/, '')

  if (configuredBasePath && normalizedPath === configuredBasePath) {
    return { basePath: configuredBasePath, action: 'signin' }
  }
  
  // Check for known actions first
  for (const action of KNOWN_ACTIONS) {
    if (normalizedPath.endsWith(`/${action}`)) {
      const basePath = normalizedPath.slice(0, -(action.length + 1))
      return { basePath, action }
    }
  }
  
  // Extract the last path segment as a potential custom action
  const segments = normalizedPath.split('/').filter(Boolean)
  if (segments.length >= 2) {
    const lastSegment = segments[segments.length - 1]
    const basePath = `/${segments.slice(0, -1).join('/')}`
    return { basePath, action: lastSegment }
  }

  if (segments.length === 1) {
    return { basePath: '', action: segments[0] }
  }
  
  // Default to signin if no action can be extracted
  return { basePath: '', action: 'signin' }
}

export function useAuthPaths() {
  let configuredBasePath = ''

  try {
    const { authConfig } = useAuthContext()
    configuredBasePath = normalizeConfiguredBasePath(authConfig.authBaseUrl)
  } catch {
    configuredBasePath = ''
  }

  const { basePath } = detectAuthBasePath(configuredBasePath)
  const detectedBasePath = ref(basePath)
  
  const buildAuthPath = (action: string, additionalParams: Record<string, string> = {}) => {
    const actionPath = action ? `${detectedBasePath.value}/${action}` : detectedBasePath.value
    return buildUrlWithPreservedParams(actionPath, additionalParams)
  }
  
  const authPaths = computed(() => ({
    signin: buildAuthPath('signin'),
    signup: buildAuthPath('signup'),
    forgotPassword: buildAuthPath('forgot-password'),
    resetPassword: buildAuthPath('reset-password'),
    magicLink: buildAuthPath('magic-link'),
    verifyOtp: buildAuthPath('verify-otp'),
    callback: buildAuthPath('callback')
  }))
  
  return {
    detectedBasePath,
    authPaths,
    buildAuthPath,
    detectAuthBasePath: () => detectAuthBasePath(configuredBasePath)
  }
}
