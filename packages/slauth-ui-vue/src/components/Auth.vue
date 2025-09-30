<template>
  <div
    :class="[
      'slauth-ui',
      `slauth-ui--${appearance}`,
      `slauth-ui--${theme}`,
      className
    ]"
    :style="style"
    data-testid="auth-container"
  >
    <!-- Confirmation status indicator -->
    <div 
      :data-testid="'confirmation-status'"
      :data-status="confirmationStatus || 'idle'"
      class="slauth-ui__confirmation-status"
      style="position: absolute; top: -9999px; left: -9999px; opacity: 0;"
    >
      {{ confirmationStatus || 'idle' }}
    </div>
    
    <div class="slauth-ui__container">
      <!-- Sign In View -->
      <SignIn
        v-if="currentView === 'sign_in'"
        :localization="mergedLocalization.sign_in"
        @switch-view="setView"
        @auth-event="handleAuthEvent"
      />

      <!-- Sign Up View -->
      <SignUp
        v-else-if="currentView === 'sign_up'"
        :localization="mergedLocalization.sign_up"
        @switch-view="setView"
        @auth-event="handleAuthEvent"
      />

      <!-- Magic Link View -->
      <MagicLink
        v-else-if="currentView === 'magic_link'"
        :localization="mergedLocalization.magic_link"
        @switch-view="setView"
        @auth-event="handleAuthEvent"
      />

      <!-- Forgot Password View -->
      <ForgotPassword
        v-else-if="currentView === 'forgotten_password'"
        :localization="mergedLocalization.forgotten_password"
        @switch-view="setView"
        @auth-event="handleAuthEvent"
      />

      <!-- Update Password View -->
      <UpdatePassword
        v-else-if="currentView === 'update_password'"
        :localization="mergedLocalization.update_password"
        @switch-view="setView"
        @auth-event="handleAuthEvent"
      />

      <!-- Verify OTP View -->
      <VerifyOtp
        v-else-if="currentView === 'verify_otp'"
        :localization="mergedLocalization.verify_otp"
        @switch-view="setView"
        @auth-event="handleAuthEvent"
      />
      <div v-else-if="currentView === 'callback'" class="slauth-ui__callback-mask">
        <div class="slauth-ui__callback-content">
          <!-- Error state -->
          <template v-if="callbackError">
            <div class="slauth-ui__callback-error">
              <div class="slauth-ui__callback-error-icon">⚠️</div>
              <h3 class="slauth-ui__callback-error-title">Authentication Failed</h3>
              <p class="slauth-ui__callback-error-message">{{ callbackError.message }}</p>
              <a
                :href="authConfig.authBaseUrl"
                class="slauth-ui__callback-error-link"
                @click="() => { callbackError = null }"
              >
                Return to Sign In
              </a>
            </div>
          </template>

          <!-- Loading state -->
          <template v-else>
            <div class="slauth-ui__callback-spinner">
              <div class="slauth-ui__callback-spinner-ring"></div>
              <div class="slauth-ui__callback-spinner-ring"></div>
              <div class="slauth-ui__callback-spinner-ring"></div>
            </div>
            <p class="slauth-ui__callback-text">Signing you in...</p>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, getCurrentInstance } from 'vue'
import type { AuthEvent } from '../types'
import { mergeLocalization } from '../localization'
import { useAuthContext } from '../composables/useAuthContext'
import { getPreservedParams, buildUrlWithPreservedParams, calculateRedirectUrl } from '../lib/redirectManager'
import SignIn from './SignIn.vue'
import SignUp from './SignUp.vue'
import MagicLink from './MagicLink.vue'
import ForgotPassword from './ForgotPassword.vue'
import UpdatePassword from './UpdatePassword.vue'
import VerifyOtp from './VerifyOtp.vue'

const props = withDefaults(defineProps<{
  view?: 'sign_in' | 'sign_up' | 'magic_link' | 'forgotten_password' | 'update_password' | 'verify_otp' | 'auto'
  className?: string
  style?: any
}>(), {
  view: 'auto',  // Default auto-detect
  className: '',
  style: () => ({})
})

const emit = defineEmits<{
  'sign-in': [event: AuthEvent]
  'sign-up': [event: AuthEvent]
  'auth-state-change': [event: AuthEvent, session: any]
  'magic-link': [event: AuthEvent]
  event: [event: AuthEvent]
}>()

// Use AuthContext
const { authClient, authConfig, localization, darkMode } = useAuthContext()

// Get Vue Router instance (if exists)
const instance = getCurrentInstance()
const router = instance?.appContext.config.globalProperties.$router
const route = instance?.appContext.config.globalProperties.$route

// Fixed convention - route actions
const KNOWN_ACTIONS = ['signup', 'signin', 'forgot-password', 'reset-password', 'magic-link', 'verify-otp', 'callback', 'confirm']

// Current view and confirmation status
const currentView = ref<'sign_in' | 'sign_up' | 'magic_link' | 'forgotten_password' | 'update_password' | 'verify_otp' | 'callback'>('sign_in')
const confirmationStatus = ref<string>('')
const callbackError = ref<{ message: string; key?: string } | null>(null)

// Debug mode detection
const isDebugMode = computed(() => {
  const urlParams = new URLSearchParams(window.location.search)
  return urlParams.get('debug') === 'true' || authConfig.debug
})

// Debug output function
const debugLog = (message: string, data?: any) => {
  if (isDebugMode.value) {
    console.info(`[Auth Debug] ${message}`, data || '')
  }
}

// Auto path detection logic
const detectAuthBasePath = (): { basePath: string, action: string } => {
  const segments = window.location.pathname.split('/').filter(Boolean)
  const lastSegment = segments[segments.length - 1]
  const isKnownAction = KNOWN_ACTIONS.includes(lastSegment)
  const basePath = isKnownAction ? `/${segments.slice(0, -1).join('/')}` : `/${segments.join('/')}`
  return { basePath, action: isKnownAction ? lastSegment : 'signin' }
}
// Auth flow navigation function
const navigateToAuthStep = (step: string, additionalParams: Record<string, string> = {}) => {
  // Use authConfig.authBaseUrl instead of auto-detection
  const authPath = `${authConfig.authBaseUrl}/${step}`
  const urlWithParams = buildUrlWithPreservedParams(authPath, additionalParams)

  if (router) {
    router.push(urlWithParams)
  } else {
    window.location.href = urlWithParams
  }
}

// Smart navigation function
const smartNavigate = (url: string) => {
  if (router) {
    // Check if it's a complete URL
    if (url.startsWith('http://') || url.startsWith('https://')) {
      // Complete URL: check if same domain
      const currentDomain = window.location.origin
      const redirectUrl = new URL(url)
      const isSameDomain = redirectUrl.origin === currentDomain

      if (isSameDomain) {
        // Same domain: use Vue Router navigation (only path part)
        router.push(redirectUrl.pathname + redirectUrl.search + redirectUrl.hash)
      } else {
        // Different domain: use window.location
        window.location.href = url
      }
    } else {
      // Relative path: ensure starts with /, use Vue Router
      const absolutePath = url.startsWith('/') ? url : `/${url}`
      router.push(absolutePath)
    }
  } else {
    window.location.href = url
  }
}

// Set view based on detected action
const setViewFromAction = (action: string) => {
  const actionToViewMap: Record<string, typeof currentView.value> = {
    'signin': 'sign_in',
    'signup': 'sign_up',
    'forgot-password': 'forgotten_password',
    'reset-password': 'update_password',
    'magic-link': 'magic_link',
    'verify-otp': 'verify_otp',
    'callback': 'callback',
    'confirm': 'sign_in'
  }
  
  const newView = actionToViewMap[action] || 'sign_in'
  currentView.value = newView
  
  debugLog('Set view', {
    action,
    newView,
    currentPath: window.location.pathname,
    currentUrl: window.location.href
  })
}

// Email confirmation handler
const handleEmailConfirmation = async () => {

  confirmationStatus.value = 'processing'

  const urlParams = new URLSearchParams(window.location.search)
  const token = urlParams.get('token')
  const redirectParam = urlParams.get('redirect')

  if (token) {
    try {
      await authClient.confirmEmail(token)
    } catch (error: any) {
      confirmationStatus.value = 'error'
      // Navigate to login page and show error message
      const finalRedirectTo = `${authConfig.authBaseUrl}/signin?error=confirmation_failed`
      smartNavigate(finalRedirectTo)
      return
    }

    confirmationStatus.value = 'success'

    // Emit confirmation success event
    const authEvent: AuthEvent = {
      event: 'EMAIL_CONFIRMED',
      data: { success: true }
    }
    handleAuthEvent(authEvent)

    // Navigate to login page and show success message
    const finalRedirectTo = calculateRedirectUrl(
      authConfig.followRedirect && !!redirectParam,
      redirectParam || undefined,
      `${authConfig.authBaseUrl}/signin?confirmed=true`
    )
    
    smartNavigate(finalRedirectTo)
  } else {
    confirmationStatus.value = 'no_token'
    currentView.value = 'sign_in'
  }
}

// OAuth callback handler
const handleOAuthCallback = async () => {
  const urlParams = new URLSearchParams(window.location.search)
  const code = urlParams.get('code')
  const redirectParam = urlParams.get('redirect')
  
  debugLog('OAuth callback processing', { 
    hasCode: !!code, 
    currentView: currentView.value 
  })
  
  if (!code) {
    debugLog('No code found, switching to sign_in')
    callbackError.value = { message: 'No authorization code found', key: 'no_code' }
    return
  }
  
  try {
    const result = await authClient.exchangeCodeForSession(code)
    
    debugLog('OAuth exchange result', { 
      hasUser: !!result?.user, 
      hasSession: !!result?.session 
    })
    
    if (!result?.user || !result?.session) {
      debugLog('Invalid result, switching to sign_in')
      callbackError.value = { message: 'Authentication failed', key: 'invalid_result' }
      return
    }
    
    const finalRedirectTo = calculateRedirectUrl(
      authConfig.followRedirect && !!redirectParam,
      redirectParam || undefined,
      authConfig.redirectTo || '/'
    )
    
    debugLog('OAuth success, redirecting to', { finalRedirectTo })
    
    const authEvent: AuthEvent = {
      event: 'SIGNED_IN',
      session: result.session
    }
    handleAuthEvent(authEvent)
    
    smartNavigate(finalRedirectTo)
  } catch (error: any) {
    debugLog('OAuth callback error', error)
    callbackError.value = {
      message: error.message || 'OAuth authentication failed',
      key: error.key
    }
  }
}

// Initialize component
onMounted(() => {

  debugLog('Component initialization started', {
    pathname: window.location.pathname,
    search: window.location.search,
    hash: window.location.hash,
    isDebugMode: isDebugMode.value
  })

  try {
    // Auto-detect path
    const { action } = detectAuthBasePath()

    debugLog('Path detection result', { action })

    // Set view based on detected action
    setViewFromAction(action)


    // If callback, auto-handle OAuth callback
    if (action === 'callback') {
      debugLog('Processing OAuth callback')
      handleOAuthCallback()
    }

    // If confirm, auto-handle email confirmation
    if (action === 'confirm') {
      debugLog('Processing email confirmation')
      handleEmailConfirmation()
    }
    debugLog('Component initialization completed', {
      finalView: currentView.value
    })
  } catch (error: any) {
    debugLog('Path detection failed', { error: error.message, stack: error.stack })
    // Use default configuration
    currentView.value = 'sign_in'
    debugLog('Using default configuration', { view: currentView.value })
  }
})


// Watch props.view changes (manual override auto-detection)
watch(() => props.view, (newView) => {
  if (newView && newView !== 'auto') {
    currentView.value = newView
  }
})

// Watch currentView changes (debug mode)
watch(currentView, (newView, oldView) => {
  debugLog('View state changed', {
    from: oldView,
    to: newView,
    timestamp: new Date().toISOString(),
    url: window.location.href
  })
})

// Watch route changes (if router exists)
if (route) {
  watch(() => route.path, (newPath) => {
    // Re-detect current path action
    try {
      const { action } = detectAuthBasePath()
      setViewFromAction(action)

      // If callback, handle OAuth callback
      if (action === 'callback') {
        handleOAuthCallback()
      }

      // If confirm, handle email confirmation
      if (action === 'confirm') {
        handleEmailConfirmation()
      }
    } catch (error) {
    }
  })
}

// Computed
const mergedLocalization = computed(() => mergeLocalization(localization as any))
const theme = computed(() => darkMode ? 'dark' : 'light')
const appearance = computed(() => authConfig.appearance || 'default')
const providers = computed(() => authConfig.providers || [])
const showLinks = computed(() => authConfig.showLinks !== false)
const magicLink = computed(() => authConfig.magicLink || false)
const showForgotPassword = computed(() => authConfig.showForgotPassword !== false)
const onlyThirdPartyProviders = computed(() => authConfig.onlyThirdPartyProviders || false)
const followRedirect = computed(() => authConfig.followRedirect !== false)
const redirectTo = computed(() => authConfig.redirectTo)

// Note: No longer need provide, because AuthConfig component already provides context

// Methods
const setView = (view: string) => {
  const newView = view as typeof currentView.value
  const oldView = currentView.value
  currentView.value = newView
  
  debugLog('View switching', {
    from: oldView,
    to: newView,
    hasRouter: !!router
  })

  // If router exists, sync update URL
  if (router) {
    const viewToActionMap: Record<typeof currentView.value, string> = {
      'sign_in': '',
      'sign_up': 'signup',
      'forgotten_password': 'forgot-password',
      'update_password': 'reset-password',
      'magic_link': 'magic-link',
      'verify_otp': 'verify-otp',
      'callback': 'callback'
    }

    const action = viewToActionMap[newView] || ''
    const authPath = action ? `${authConfig.authBaseUrl}/${action}` : authConfig.authBaseUrl
    const urlWithParams = buildUrlWithPreservedParams(authPath)

    debugLog('URL updated', { authPath, urlWithParams })

    // Use replace instead of push to avoid stacking in history
    router.replace(urlWithParams)
  }
}


const handleAuthFlowResponse = (response: any) => {
  const { data, error, flow } = response
  
  if (flow) {
    
    switch (flow.type) {
      case 'email_verification_required':
        // Email verification required
        navigateToAuthStep('verify-email', {
          email: data?.user?.email || '',
          flow_id: flow.id || ''
        })
        break

      case 'otp_required':
        // OTP verification required
        navigateToAuthStep('verify-otp', {
          flow_id: flow.id || '',
          method: flow.method || 'email'
        })
        break

      case 'mfa_setup_required':
        // MFA setup required
        navigateToAuthStep('mfa-setup', {
          flow_id: flow.id || ''
        })
        break

      case 'completed':
        // Auth flow completed, perform final redirect
        const preserved = getPreservedParams()
        const finalRedirectTo = calculateRedirectUrl(
          authConfig.followRedirect && !!preserved.redirect,
          preserved.redirect,
          authConfig.redirectTo || '/'
        )

        smartNavigate(finalRedirectTo)
        break

      default:
    }
  } else if (data?.user && data?.session) {
    // No flow indication, direct auth success
    const preserved = getPreservedParams()
    const finalRedirectTo = calculateRedirectUrl(
      authConfig.followRedirect && !!preserved.redirect,
      preserved.redirect,
      authConfig.redirectTo || '/'
    )

    smartNavigate(finalRedirectTo)
  }
}

const handleAuthEvent = (event: AuthEvent) => {
  // Emit generic event
  emit('event', event)
  
  switch (event.event) {
    case 'SIGNED_IN':
      emit('sign-in', event)
      emit('auth-state-change', event, event.session)
      // Check if flow response data exists
      if ((event as any).flowResponse) {
        handleAuthFlowResponse((event as any).flowResponse)
      } else if (authConfig.followRedirect && event.session?.user) {
        // Traditional handling: direct redirect
        const preserved = getPreservedParams()
        const finalRedirectTo = calculateRedirectUrl(
          authConfig.followRedirect && !!preserved.redirect,
          preserved.redirect,
          authConfig.redirectTo || '/'
        )
        smartNavigate(finalRedirectTo)
      }
      break
    case 'SIGNED_UP':
      emit('sign-up', event)
      emit('auth-state-change', event, event.session)
      // Check if flow response data exists
      if ((event as any).flowResponse) {
        handleAuthFlowResponse((event as any).flowResponse)
      } else if (authConfig.followRedirect && event.session?.user) {
        // Traditional handling: direct redirect
        const preserved = getPreservedParams()
        const finalRedirectTo = calculateRedirectUrl(
          authConfig.followRedirect && !!preserved.redirect,
          preserved.redirect,
          authConfig.redirectTo || '/'
        )
        smartNavigate(finalRedirectTo)
      }
      break
    case 'AUTH_ID_TOKEN':
      emit('magic-link', event)
      break
    case 'TOKEN_REFRESHED':
    case 'USER_UPDATED':
    case 'SIGNED_OUT':
      emit('auth-state-change', event, event.session)
      break
  }
}
</script>

<style scoped>
.slauth-ui {
  font-family: var(--auth-ui-font-family, system-ui, -apple-system, sans-serif);
  color: var(--auth-ui-text);
  background-color: var(--auth-ui-background);
  transition: background-color 0.3s ease, color 0.3s ease;
}

.slauth-ui__container {
  max-width: 400px;
  margin: 0 auto;
  padding: 1.5rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: var(--auth-ui-radius-md);
  background-color: var(--auth-ui-background);
  box-shadow: var(--auth-ui-shadow-md);
  transition: all 0.3s ease;
}

.slauth-ui--minimal .slauth-ui__container {
  border: none;
  padding: 0;
  box-shadow: none;
}

/* Dark mode support */
[data-theme="dark"] .slauth-ui {
  color: var(--auth-ui-text);
  background-color: var(--auth-ui-background);
}

[data-theme="dark"] .slauth-ui__container {
  background-color: var(--auth-ui-background);
  border-color: var(--auth-ui-border);
}

/* Auto theme support */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme]) .slauth-ui {
    color: var(--auth-ui-text);
    background-color: var(--auth-ui-background);
  }

  :root:not([data-theme]) .slauth-ui__container {
    background-color: var(--auth-ui-background);
    border-color: var(--auth-ui-border);
  }
}

/* Callback loading state */
.slauth-ui__callback-mask {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  padding: 2rem;
  background-color: var(--auth-ui-background);
}

.slauth-ui__callback-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1.5rem;
}

.slauth-ui__callback-spinner {
  position: relative;
  width: 64px;
  height: 64px;
}

.slauth-ui__callback-spinner-ring {
  position: absolute;
  width: 100%;
  height: 100%;
  border: 3px solid transparent;
  border-top-color: var(--auth-ui-primary, #3b82f6);
  border-radius: 50%;
  animation: slauth-ui-spin 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
}

.slauth-ui__callback-spinner-ring:nth-child(1) {
  animation-delay: -0.45s;
  border-top-color: var(--auth-ui-primary, #3b82f6);
}

.slauth-ui__callback-spinner-ring:nth-child(2) {
  animation-delay: -0.3s;
  border-top-color: var(--auth-ui-primary-light, #60a5fa);
  width: 85%;
  height: 85%;
  top: 7.5%;
  left: 7.5%;
}

.slauth-ui__callback-spinner-ring:nth-child(3) {
  animation-delay: -0.15s;
  border-top-color: var(--auth-ui-primary-lighter, #93c5fd);
  width: 70%;
  height: 70%;
  top: 15%;
  left: 15%;
}

@keyframes slauth-ui-spin {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

.slauth-ui__callback-text {
  margin: 0;
  font-size: 0.875rem;
  color: var(--auth-ui-text-muted, #6b7280);
  font-weight: 500;
  animation: slauth-ui-pulse 2s ease-in-out infinite;
}

@keyframes slauth-ui-pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

/* Callback error state */
.slauth-ui__callback-error {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  text-align: center;
  max-width: 400px;
  padding: 2rem;
}

.slauth-ui__callback-error-icon {
  font-size: 3rem;
  line-height: 1;
}

.slauth-ui__callback-error-title {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--auth-ui-text, #111827);
}

.slauth-ui__callback-error-message {
  margin: 0;
  font-size: 0.875rem;
  color: var(--auth-ui-text-muted, #6b7280);
  line-height: 1.5;
}

.slauth-ui__callback-error-link {
  margin-top: 0.5rem;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--auth-ui-primary, #3b82f6);
  text-decoration: none;
  transition: color 0.2s ease;
}

.slauth-ui__callback-error-link:hover {
  color: var(--auth-ui-primary-hover, #2563eb);
  text-decoration: underline;
}

.slauth-ui__callback-error-link:focus {
  outline: 2px solid var(--auth-ui-primary, #3b82f6);
  outline-offset: 2px;
  border-radius: 2px;
}
</style>
