<template>
  <div>
    <button 
      @click="handleGoogleLogin"
      :style="buttonStyle"
      :class="buttonClass"
      :disabled="disabled"
    >
      <svg :style="iconStyle" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
      {{ buttonText }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Localization, Theme } from '../types'
import { interpolate, getProviderDisplayName } from '../localization'
import { useOAuthButtonStyles } from '../composables/useOAuthButtonStyles'
import { useAuthContext } from '../composables/useAuthContext'

// Emits
const emit = defineEmits<{
  redirect: [url: string]
  error: [error: Error]
  success: [data: any]
}>()

// Props
const props = defineProps<{
  localization?: Localization['sign_in'] 
  disabled?: boolean 
  loading?: boolean 
}>()


const { authClient, authConfig } = useAuthContext()
const client = authClient


const callbackUrl = computed(() => `${authConfig.authBaseUrl}/callback`)
const redirectTo = computed(() => authConfig.redirectTo)

console.info('callbackUrl', callbackUrl.value)


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
      provider: getProviderDisplayName('google')
    })
  }
  
  
  return 'Sign in with Google'
})


const buttonStyle = computed(() => baseButtonStyle.value)


const buttonClass = computed(() => {
  const classes = ['oauth-button', 'oauth-button--google']
  
  if (props.disabled) {
    classes.push('oauth-button--disabled')
  }
  
  if (props.loading) {
    classes.push('oauth-button--loading')
  }
  
  return classes.join(' ')
})

// Methods
const handleGoogleLogin = async () => {
  try {
    
    const scope = authConfig?.scope || 'openid email profile'
    const googleClientId = authConfig?.googleClientId || 'YOUR_GOOGLE_CLIENT_ID'

    
    const oauthData = await client.signInWithOAuth({
      provider: 'google',
      options: {
        redirect_uri: callbackUrl.value
      }
    })

    if (!oauthData.flow_id) {
      throw new Error('No flow ID received')
    }

    
    const googleOAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth')
    googleOAuthUrl.searchParams.set('client_id', oauthData.config?.client_id || googleClientId )
    googleOAuthUrl.searchParams.set('redirect_uri', callbackUrl.value)
    googleOAuthUrl.searchParams.set('response_type', 'code')
    googleOAuthUrl.searchParams.set('scope', scope)
    googleOAuthUrl.searchParams.set('state', oauthData.flow_id) 

    console.info('googleOAuthUrl', googleOAuthUrl.toString())
    
    
    
    window.location.href = googleOAuthUrl.toString()
  } catch (error) {
    console.error('OAuth initiation failed:', error)
    emit('error', error instanceof Error ? error : new Error(String(error)))
  }
}

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
