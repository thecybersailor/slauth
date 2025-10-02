<template>
  <div>
    <button 
      @click="handleMockLogin"
      :style="buttonStyle"
      :class="buttonClass"
      :disabled="disabled"
      data-testid="oauth-button-mock"
    >
      <svg :style="iconStyle" viewBox="0 0 24 24">
        <path fill="#6B7280" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/>
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
import { useOAuthSignIn } from '../composables/useOAuthSignIn'

const emit = defineEmits<{
  redirect: [url: string]
  error: [error: Error]
  success: [data: any]
}>()

const props = defineProps<{
  localization?: Localization['sign_in'] 
  disabled?: boolean 
  loading?: boolean 
}>()

const { authConfig } = useAuthContext()
const { signInWithOAuth } = useOAuthSignIn()

const callbackUrl = computed(() => `${authConfig.authBaseUrl}/callback`)

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
      provider: 'Mock OAuth'
    })
  }
  return 'Sign in with Mock OAuth'
})

const buttonStyle = computed(() => baseButtonStyle.value)

const buttonClass = computed(() => {
  const classes = ['oauth-button', 'oauth-button--mock']
  
  if (props.disabled) {
    classes.push('oauth-button--disabled')
  }
  
  if (props.loading) {
    classes.push('oauth-button--loading')
  }
  
  return classes.join(' ')
})

const handleMockLogin = async () => {
  if (props.disabled || props.loading) return
  
  const mockOAuthServerUrl = import.meta.env.VITE_MOCK_OAUTH_SERVER || 'http://localhost:8080/mock-oauth'
  const mockClientId = 'mock-client-id'

  const oauthData = await signInWithOAuth('mock', {
    redirect_uri: callbackUrl.value
  })

  if (!oauthData.flow_id) {
    emit('error', new Error('No flow ID received'))
    return
  }

  const mockOAuthUrl = new URL(`${mockOAuthServerUrl}/authorize`)
  mockOAuthUrl.searchParams.set('client_id', oauthData.config?.client_id || mockClientId)
  mockOAuthUrl.searchParams.set('redirect_uri', callbackUrl.value)
  mockOAuthUrl.searchParams.set('response_type', 'code')
  mockOAuthUrl.searchParams.set('scope', 'openid email profile')
  mockOAuthUrl.searchParams.set('state', oauthData.flow_id)

  console.info('mockOAuthUrl', mockOAuthUrl.toString())
  
  window.location.href = mockOAuthUrl.toString()
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
</style>

