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
        @auth-event="handleAuthEvent"
      />

      <!-- Sign Up View -->
      <SignUp
        v-else-if="currentView === 'sign_up'"
        :localization="mergedLocalization.sign_up"
        @auth-event="handleAuthEvent"
      />

      <!-- Magic Link View -->
      <MagicLink
        v-else-if="currentView === 'magic_link'"
        :localization="mergedLocalization.magic_link"
        @auth-event="handleAuthEvent"
      />

      <!-- Forgot Password View -->
      <ForgotPassword
        v-else-if="currentView === 'forgotten_password'"
        :localization="mergedLocalization.forgotten_password"
        @auth-event="handleAuthEvent"
      />

      <!-- Update Password View -->
      <UpdatePassword
        v-else-if="currentView === 'update_password'"
        :localization="mergedLocalization.update_password"
        @auth-event="handleAuthEvent"
      />

      <!-- Verify OTP View -->
      <VerifyOtp
        v-else-if="currentView === 'verify_otp'"
        :localization="mergedLocalization.verify_otp"
        @auth-event="handleAuthEvent"
      />

      <!-- Email Confirmed View -->
      <div v-else-if="currentView === 'confirmed'" class="slauth-ui__confirmed" data-testid="confirmed-view">
        <div class="slauth-ui__confirmed-content">
          <div class="slauth-ui__confirmed-icon">✅</div>
          <h2 class="slauth-ui__confirmed-title" data-testid="confirmed-title">
            Email Confirmed Successfully
          </h2>
          <p class="slauth-ui__confirmed-message" data-testid="confirmed-message">
            Your email has been verified. You can now sign in to your account.
          </p>
          <a
            :href="`${authConfig.authBaseUrl}/signin`"
            class="slauth-ui__confirmed-link"
            data-testid="confirmed-signin-link"
          >
            Continue to Sign In
          </a>
        </div>
      </div>

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
import { useAuthPaths, KNOWN_ACTIONS } from '../composables/useAuthPaths'
import { buildUrlWithPreservedParams } from '../lib/redirectManager'
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
  'email-confirmed': [event: AuthEvent]
  event: [event: AuthEvent]
}>()

// Use AuthContext
const { authClient, authConfig, localization, darkMode } = useAuthContext()

// Use AuthPaths
const { detectedBasePath, buildAuthPath, detectAuthBasePath } = useAuthPaths()

// Get Vue Router instance (if exists)
const instance = getCurrentInstance()
const router = instance?.appContext.config.globalProperties.$router
const route = instance?.appContext.config.globalProperties.$route

// Current view and confirmation status
const currentView = ref<'sign_in' | 'sign_up' | 'magic_link' | 'forgotten_password' | 'update_password' | 'verify_otp' | 'callback' | 'confirmed'>('sign_in')
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

// Auth flow navigation function
const navigateToAuthStep = (step: string, additionalParams: Record<string, string> = {}) => {
  const urlWithParams = buildAuthPath(step, additionalParams)

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
    'confirm': 'sign_in',
    'confirmed': 'confirmed'
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

    // Navigate to confirmed view instead of signin page
    currentView.value = 'confirmed'

    // Update URL to reflect confirmed state without redirect params
    const newUrl = `${authConfig.authBaseUrl}/confirmed`
    window.history.replaceState({}, '', newUrl)
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
      hasSession: !!result?.session,
      hasRedirectTo: !!(result as any)?.redirect_to
    })
    
    if (!result?.user || !result?.session) {
      debugLog('Invalid result, switching to sign_in')
      callbackError.value = { message: 'Authentication failed', key: 'invalid_result' }
      return
    }
    
    // Use backend-validated redirect_to
    const finalRedirectTo = (result as any).redirect_to || authConfig.redirectTo || '/'
    
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
        // Auth flow completed, use backend-validated redirect_to
        const redirectTo = data?.redirect_to || authConfig.redirectTo || '/'
        smartNavigate(redirectTo)
        break

      default:
    }
  } else if (data?.user && data?.session) {
    // No flow indication, direct auth success
    // Use backend-validated redirect_to
    const redirectTo = data?.redirect_to || authConfig.redirectTo || '/'
    smartNavigate(redirectTo)
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
        // Traditional handling: use backend-validated redirect_to if available
        const redirectTo = (event as any).redirect_to || authConfig.redirectTo || '/'
        smartNavigate(redirectTo)
      }
      break
    case 'SIGNED_UP':
      emit('sign-up', event)
      emit('auth-state-change', event, event.session)
      // Check if flow response data exists
      if ((event as any).flowResponse) {
        handleAuthFlowResponse((event as any).flowResponse)
      } else if (authConfig.followRedirect && event.session?.user) {
        // Traditional handling: use backend-validated redirect_to if available
        const redirectTo = (event as any).redirect_to || authConfig.redirectTo || '/'
        smartNavigate(redirectTo)
      }
      break
    case 'AUTH_ID_TOKEN':
      emit('magic-link', event)
      break
    case 'EMAIL_CONFIRMED':
      emit('email-confirmed', event)
      // Show success notification for email confirmation
      debugLog('Email confirmation successful', event)
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

/* Email Confirmed View */
.slauth-ui__confirmed {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  padding: 2rem;
}

.slauth-ui__confirmed-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1.5rem;
  text-align: center;
  max-width: 400px;
  padding: 2rem;
}

.slauth-ui__confirmed-icon {
  font-size: 4rem;
  line-height: 1;
  animation: slauth-ui-bounce 1s ease-in-out;
}

.slauth-ui__confirmed-title {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text, #111827);
}

.slauth-ui__confirmed-message {
  margin: 0;
  font-size: 1rem;
  color: var(--auth-ui-text-muted, #6b7280);
  line-height: 1.5;
}

.slauth-ui__confirmed-link {
  margin-top: 1rem;
  padding: 0.75rem 1.5rem;
  font-size: 0.875rem;
  font-weight: 500;
  color: white;
  background-color: var(--auth-ui-primary, #3b82f6);
  text-decoration: none;
  border-radius: var(--auth-ui-radius-md, 0.375rem);
  transition: background-color 0.2s ease, transform 0.1s ease;
  display: inline-block;
}

.slauth-ui__confirmed-link:hover {
  background-color: var(--auth-ui-primary-hover, #2563eb);
  transform: translateY(-1px);
}

.slauth-ui__confirmed-link:focus {
  outline: 2px solid var(--auth-ui-primary, #3b82f6);
  outline-offset: 2px;
}

.slauth-ui__confirmed-link:active {
  transform: translateY(0);
}

@keyframes slauth-ui-bounce {
  0%, 20%, 50%, 80%, 100% {
    transform: translateY(0);
  }
  40% {
    transform: translateY(-10px);
  }
  60% {
    transform: translateY(-5px);
  }
}
</style>
