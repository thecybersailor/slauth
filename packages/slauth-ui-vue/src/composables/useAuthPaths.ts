import { ref, computed } from 'vue'
import { buildUrlWithPreservedParams } from '../lib/redirectManager'

export const KNOWN_ACTIONS = ['signup', 'signin', 'forgot-password', 'reset-password', 'magic-link', 'verify-otp', 'callback', 'confirm', 'confirmed']

const detectAuthBasePath = (): { basePath: string, action: string } => {
  const currentPath = window.location.pathname
  
  for (const action of KNOWN_ACTIONS) {
    if (currentPath.endsWith(`/${action}`)) {
      const basePath = currentPath.slice(0, -(action.length + 1)) 
      return { basePath, action }
    }
  }
  
  if (!KNOWN_ACTIONS.some(action => currentPath.includes(`/${action}`))) {
    if (!currentPath.endsWith('/')) {
      window.location.href = currentPath + '/'
      return { basePath: currentPath, action: 'signin' } 
    }
    const basePath = currentPath.replace(/\/$/, '') 
    return { basePath, action: 'signin' } 
  }
  
  throw new Error(`Unable to detect valid authentication base path from current path "${currentPath}"`)
}

export function useAuthPaths() {
  const { basePath } = detectAuthBasePath()
  const detectedBasePath = ref(basePath)
  console.info('detectedBasePath', detectedBasePath.value)
  
  
  const buildAuthPath = (action: string, additionalParams: Record<string, string> = {}) => {
    const actionPath = action ? `${detectedBasePath.value}/${action}` : detectedBasePath.value
    return buildUrlWithPreservedParams(actionPath, additionalParams)
  }
  
  const authPaths = computed(() => ({
    signin: buildAuthPath(''),
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
