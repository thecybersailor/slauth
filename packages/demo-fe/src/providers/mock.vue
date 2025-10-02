<template>
  <SocialButton
    :loading="loading"
    :error="error"
    data-testid="oauth-button-mock"
    @click="handleMockLogin"
  >
    <template #icon>
      <svg viewBox="0 0 24 24">
        <path fill="#6B7280" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/>
      </svg>
    </template>
    Sign in with Mock OAuth
  </SocialButton>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useAuthContext, useOAuthSignIn, useAuthState, SocialButton } from '@cybersailor/slauth-ui-vue'

const emit = defineEmits<{
  redirect: [url: string]
  error: [error: Error]
  success: [data: any]
}>()

const { authConfig } = useAuthContext()
const { signInWithOAuth } = useOAuthSignIn()
const authState = useAuthState()

const callbackUrl = computed(() => `${authConfig.authBaseUrl}/callback`)
const loading = computed(() => authState?.formState?.loadingSource === 'oauth.mock')
const error = ref<string>('')

const handleMockLogin = async () => {
  if (loading.value) return
  
  error.value = ''
  authState?.reset()
  
  try {
    const mockOAuthServerUrl = import.meta.env.VITE_MOCK_OAUTH_SERVER || 'http://localhost:8080/mock-oauth'
    const mockClientId = 'mock-client-id'

    const oauthData = await signInWithOAuth('mock', {
      redirect_uri: callbackUrl.value
    })

    if (!oauthData.flow_id) {
      const err = new Error('No flow ID received')
      error.value = err.message
      emit('error', err)
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
  } catch (err: any) {
    error.value = err.message || 'OAuth sign-in failed'
    authState?.reset()
    emit('error', err instanceof Error ? err : new Error(String(err)))
  }
}
</script>

