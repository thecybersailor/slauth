<template>
    <div>
        <button 
            @click="handleFacebookLogin"
            :style="buttonStyle"
            :class="buttonClass"
            :disabled="disabled"
            data-testid="oauth-button-facebook"
        >
            <svg :style="iconStyle" viewBox="0 0 24 24">
                <path fill="#1877F2" d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
            </svg>
            {{ buttonText }}
        </button>
    </div>
</template>
<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import type { Localization, Theme } from '../types'
import { interpolate, getProviderDisplayName } from '../localization'
import { useOAuthButtonStyles } from '../composables/useOAuthButtonStyles'
import { useAuthContext } from '../composables/useAuthContext'


declare global {
  const FB: any
}

// Props
const props = defineProps<{
  localization?: Localization['sign_in'] 
  disabled?: boolean 
  loading?: boolean 
}>()


const { authClient, authConfig } = useAuthContext()

// Emits
const emit = defineEmits<{
  credential: [data: any]
  error: [error: Error]
}>()

// State
const inited = ref(false)
const scriptLoaded = ref(false)


const variables = computed(() => {
  const appearance = authConfig?.appearance
  if (typeof appearance === 'object' && appearance?.variables) {
    return appearance.variables.default || {}
  }
  return {}
})


const theme = computed(() => {
  const appearance = authConfig?.appearance
  if (typeof appearance === 'object' && appearance?.theme) {
    return appearance.theme
  }
  return 'light'
})


const {
  baseButtonStyle,
  hoverStyle,
  activeStyle,
  disabledStyle,
  iconStyle
} = useOAuthButtonStyles(variables, theme.value as Theme)


const buttonText = computed(() => {
  
  if (props.localization?.social_provider_text) {
    return interpolate(props.localization.social_provider_text, {
      provider: getProviderDisplayName('facebook')
    })
  }
  
  
  return 'Sign in with Facebook'
})


const buttonStyle = computed(() => baseButtonStyle.value)


const buttonClass = computed(() => {
  const classes = ['oauth-button', 'oauth-button--facebook']
  
  if (props.disabled) {
    classes.push('oauth-button--disabled')
  }
  
  if (props.loading) {
    classes.push('oauth-button--loading')
  }
  
  return classes.join(' ')
})

// Methods
const handleFacebookLogin = async () => {
  if (props.disabled || props.loading) return
  
  try {
    
    const clientId = authConfig?.facebookClientId || import.meta.env.VITE_FACEBOOK_CLIENT_ID || 'your-facebook-app-id'
    
    
    const oauthData = await authClient.signInWithOAuth({
      provider: 'facebook'
    })

    if (!oauthData.flow_id) {
      throw new Error('No flow ID received')
    }

    
    const facebookOAuthUrl = new URL('https://www.facebook.com/v18.0/dialog/oauth')
    facebookOAuthUrl.searchParams.set('client_id', oauthData.config?.client_id || clientId)
    facebookOAuthUrl.searchParams.set('redirect_uri', authConfig?.redirectTo || `${window.location.origin}/auth/callback`)
    facebookOAuthUrl.searchParams.set('response_type', 'code')
    facebookOAuthUrl.searchParams.set('scope', 'email,public_profile')
    facebookOAuthUrl.searchParams.set('state', oauthData.flow_id)
    
    
    window.location.href = facebookOAuthUrl.toString()
  } catch (error) {
    console.error('Facebook OAuth initiation failed:', error)
    emit('error', error instanceof Error ? error : new Error(String(error)))
  }
}

const init = () => {
  if (scriptLoaded.value && !inited.value) {
    inited.value = true
    initFacebook()
  }
}

const initFacebook = () => {
  
  const clientId = authConfig?.facebookClientId || import.meta.env.VITE_FACEBOOK_CLIENT_ID || 'your-facebook-app-id'
  
  FB.init({
    appId: clientId,
    cookie: true,
    xfbml: true,
    version: 'v1.0'
  })

  FB.AppEvents.logPageView()
  FB.Event.subscribe('auth.authResponseChange', handleCredentialResponse)
}

const loadScript = () => {
  const js = document.createElement('script')
  js.id = 'facebook-jssdk'
  js.src = 'https://connect.facebook.net/en_US/sdk.js'
  js.async = true
  js.onload = () => {
    scriptLoaded.value = true
  }
  document.body.appendChild(js)
}

const handleCredentialResponse = (response: any) => {
  if (response.status === 'connected') {
    emit('credential', response.authResponse)
  }
}

// Watchers
watch(scriptLoaded, () => {
  init()
})

// Lifecycle
onMounted(() => {
  loadScript()
})
</script>

<style scoped>
.oauth-button {
  position: relative;
  overflow: hidden;
}

.oauth-button:hover:not(.oauth-button--disabled) {
  background-color: v-bind('hoverStyle.backgroundColor') !important;
  border-color: v-bind('hoverStyle.borderColor') !important;
  box-shadow: v-bind('hoverStyle.boxShadow') !important;
}

.oauth-button:active:not(.oauth-button--disabled) {
  background-color: v-bind('activeStyle.backgroundColor') !important;
  border-color: v-bind('activeStyle.borderColor') !important;
  box-shadow: v-bind('activeStyle.boxShadow') !important;
}

.oauth-button--disabled {
  opacity: v-bind('disabledStyle.opacity') !important;
  cursor: v-bind('disabledStyle.cursor') !important;
  box-shadow: v-bind('disabledStyle.boxShadow') !important;
}

.oauth-button--loading {
  position: relative;
}

.oauth-button--loading::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 16px;
  height: 16px;
  margin: -8px 0 0 -8px;
  border: 2px solid transparent;
  border-top: 2px solid currentColor;
  border-radius: 50%;
  animation: oauth-button-spin 1s linear infinite;
}

@keyframes oauth-button-spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

</style>
