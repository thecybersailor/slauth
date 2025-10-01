import { ref, computed } from 'vue'
import { buildUrlWithPreservedParams } from '../lib/redirectManager'

export const KNOWN_ACTIONS = ['signup', 'signin', 'forgot-password', 'reset-password', 'magic-link', 'verify-otp', 'callback', 'confirm', 'confirmed']

const detectAuthBasePath = (): { basePath: string, action: string } => {
  const currentPath = window.location.pathname
  console.log('[DEBUG] detectAuthBasePath called', { currentPath, KNOWN_ACTIONS })
  
  for (const action of KNOWN_ACTIONS) {
    if (currentPath.endsWith(`/${action}`)) {
      const basePath = currentPath.slice(0, -(action.length + 1)) 
      console.log('[DEBUG] Matched action from path', { action, basePath, currentPath })
      return { basePath, action }
    }
  }
  
  if (!KNOWN_ACTIONS.some(action => currentPath.includes(`/${action}`))) {
    console.log('[DEBUG] No known action found in path')
    const basePath = currentPath.replace(/\/$/, '')
    console.log('[DEBUG] Using default signin action', { basePath })
    return { basePath, action: 'signin' } 
  }
  
  console.error('[DEBUG] Unable to detect auth base path', { currentPath })
  throw new Error(`Unable to detect valid authentication base path from current path "${currentPath}"`)
}

export function useAuthPaths() {
  const { basePath } = detectAuthBasePath()
  const detectedBasePath = ref(basePath)
  console.info('detectedBasePath', detectedBasePath.value)
  
  
  const buildAuthPath = (action: string, additionalParams: Record<string, string> = {}) => {
    const actionPath = action ? `${detectedBasePath.value}/${action}` : detectedBasePath.value
    console.log('[DEBUG] buildAuthPath called', { action, basePath: detectedBasePath.value, actionPath, additionalParams })
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
