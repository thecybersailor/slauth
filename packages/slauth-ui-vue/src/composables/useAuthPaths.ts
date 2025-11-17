import { ref, computed } from 'vue'
import { buildUrlWithPreservedParams } from '../lib/redirectManager'

export const KNOWN_ACTIONS = ['signup', 'signin', 'forgot-password', 'reset-password', 'magic-link', 'verify-otp', 'callback', 'confirm', 'confirmed']

const detectAuthBasePath = (): { basePath: string, action: string } => {
  const currentPath = window.location.pathname
  
  // Check for known actions first
  for (const action of KNOWN_ACTIONS) {
    if (currentPath.endsWith(`/${action}`)) {
      const basePath = currentPath.slice(0, -(action.length + 1)) 
      return { basePath, action }
    }
  }
  
  // Extract the last path segment as a potential custom action
  const segments = currentPath.replace(/\/$/, '').split('/')
  if (segments.length >= 2) {
    const lastSegment = segments[segments.length - 1]
    const basePath = segments.slice(0, -1).join('/')
    return { basePath, action: lastSegment }
  }
  
  // Default to signin if no action can be extracted
  return { basePath: currentPath.replace(/\/$/, ''), action: 'signin' }
}

export function useAuthPaths() {
  const { basePath } = detectAuthBasePath()
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
    detectAuthBasePath
  }
}
