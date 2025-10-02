<template>
  <SocialButton
    :loading="loading"
    :error="error"
    data-testid="oauth-button-facebook"
    @click="handleFacebookLogin"
  >
    <template #icon>
      <svg viewBox="0 0 24 24">
        <path fill="#1877F2" d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
      </svg>
    </template>
    {{ buttonText }}
  </SocialButton>
</template>
<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import type { Localization } from '../types'
import { interpolate, getProviderDisplayName } from '../localization'
import { useAuthContext } from '../composables/useAuthContext'
import { useAuthState } from '../composables/useAuthState'
import SocialButton from '../components/ui/SocialButton.vue'

declare global {
  const FB: any
}

const props = defineProps<{
  localization?: Localization['sign_in']
}>()

const { authClient, authConfig } = useAuthContext()
const authState = useAuthState()

const emit = defineEmits<{
  credential: [data: any]
  error: [error: Error]
}>()

const inited = ref(false)
const scriptLoaded = ref(false)
const loading = computed(() => authState?.formState?.loadingSource === 'oauth.facebook')
const error = ref<string>('')

const buttonText = computed(() => {
  if (props.localization?.social_provider_text) {
    return interpolate(props.localization.social_provider_text, {
      provider: getProviderDisplayName('facebook')
    })
  }
  return 'Sign in with Facebook'
})

const handleFacebookLogin = async () => {
  if (loading.value) return
  
  error.value = ''
  authState?.reset()
  
  try {
    const clientId = authConfig?.facebookClientId || import.meta.env.VITE_FACEBOOK_CLIENT_ID || 'your-facebook-app-id'
    
    const oauthData = await authClient.signInWithOAuth({
      provider: 'facebook'
    })

    if (!oauthData.flow_id) {
      const err = new Error('No flow ID received')
      error.value = err.message
      emit('error', err)
      return
    }

    const facebookOAuthUrl = new URL('https://www.facebook.com/v18.0/dialog/oauth')
    facebookOAuthUrl.searchParams.set('client_id', oauthData.config?.client_id || clientId)
    facebookOAuthUrl.searchParams.set('redirect_uri', authConfig?.redirectTo || `${window.location.origin}/auth/callback`)
    facebookOAuthUrl.searchParams.set('response_type', 'code')
    facebookOAuthUrl.searchParams.set('scope', 'email,public_profile')
    facebookOAuthUrl.searchParams.set('state', oauthData.flow_id)
    
    window.location.href = facebookOAuthUrl.toString()
  } catch (err: any) {
    error.value = err.message || 'OAuth sign-in failed'
    authState?.reset()
    emit('error', err instanceof Error ? err : new Error(String(err)))
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

onMounted(() => {
  loadScript()
})
</script>
