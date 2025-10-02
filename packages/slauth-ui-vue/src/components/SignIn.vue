<template>
  <div class="aira-sign-in">
    <!-- Header Slot -->
    <div v-if="$slots.header" class="aira-sign-in__header-slot">
      <slot name="header" :view="'sign_in'" />
    </div>
    
    <!-- Default Header -->
    <div v-else class="aira-sign-in__header">
        <h2 class="aira-sign-in__title">Sign in to your account</h2>
    </div>

    <!-- Social Providers -->
    <SocialProviders
      v-if="providers && providers.length > 0"
      :localization="localization"
      @auth-event="handleAuthEvent"
    />

    <!-- Divider -->
    <Divider
      v-if="!onlyThirdPartyProviders && providers && providers.length > 0"
      text="or"
    />

    <!-- Email/Password Form -->
    <form
      v-if="!onlyThirdPartyProviders"
      class="aira-sign-in__form"
      @submit.prevent="handleSubmit"
      data-testid="signin-form"
      :data-status="authState.formState.loading ? 'loading' : 'idle'"
    >
      <Message
        v-if="authState.formState.message"
        :type="authState.formState.messageType"
        :message="authState.formState.message"
        :error-key="authState.formState.messageKey"
        data-testid="auth-message"
      />

      <Input
        v-model="form.email"
        type="email"
        :label="localization?.email_label || 'Email'"
        :placeholder="localization?.email_input_placeholder || 'Enter your email'"
        :error="authState.getError('email')"
        :disabled="authState.formState.loading"
        auto-complete="email"
        required
        data-testid="signin-email-input"
      />

      <Input
        v-model="form.password"
        type="password"
        :label="localization?.password_label || 'Password'"
        :placeholder="localization?.password_input_placeholder || 'Enter your password'"
        :error="authState.getError('password')"
        :disabled="authState.formState.loading"
        auto-complete="current-password"
        required
        data-testid="signin-password-input"
      />

      <Button
        type="submit"
        variant="primary"
        size="md"
        full-width
        :loading="authState.formState.loadingSource === 'form'"
        :disabled="authState.formState.loading"
        data-testid="signin-button"
      >
        {{ authState.formState.loadingSource === 'form' ? (localization?.loading_button_label || 'Signing in...') : (localization?.button_label || 'Sign in') }}
      </Button>

      <!-- Forgot Password Link -->
      <div
        v-if="showForgotPassword"
        class="aira-sign-in__forgot-password"
      >
        <Anchor
          :href="authPaths.forgotPassword"
          text="Forgot your password?"
          data-testid="forgot-password-link"
        />
      </div>

      <!-- Magic Link -->
      <div
        v-if="magicLink"
        class="aira-sign-in__magic-link"
      >
        <Anchor
          :href="authPaths.magicLink"
          text="Send a magic link email instead"
        />
      </div>
    </form>

    <!-- Footer Slot -->
    <div v-if="$slots.footer" class="aira-sign-in__footer-slot">
      <slot name="footer" :view="'sign_in'" />
    </div>
    
    <!-- Default Footer -->
    <div
      v-else-if="showLinks"
      class="aira-sign-in__footer"
    >
      <Anchor
        :href="authPaths.signup"
        :text="localization?.link_text || 'Don\'t have an account? Sign up'"
        data-testid="signup-redirect-link"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, computed, provide } from 'vue'
import type { AuthEvent, Localization } from '../types'
import { useAuth } from '../composables/useAuth'
import { createAuthState } from '../composables/useAuthState'
import { useAuthPaths } from '../composables/useAuthPaths'
import { useAuthContext } from '../composables/useAuthContext'
import { getRedirectParameter } from '../lib/redirectManager'
import Input from './ui/Input.vue'
import Button from './ui/Button.vue'
import Message from './ui/Message.vue'
import Divider from './ui/Divider.vue'
import Anchor from './ui/Anchor.vue'
import SocialProviders from './SocialProviders.vue'

// Props
interface Props {
  localization: Localization['sign_in']
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  className: ''
})

// Use AuthContext
const { authClient, authConfig } = useAuthContext()

// Get configuration from authConfig
const providers = computed(() => authConfig.providers || [])
const showLinks = computed(() => authConfig.showLinks !== false)
const magicLink = computed(() => authConfig.magicLink || false)
const showForgotPassword = computed(() => authConfig.showForgotPassword !== false)
const onlyThirdPartyProviders = computed(() => authConfig.onlyThirdPartyProviders || false)

// Emits
const emit = defineEmits<{
  'switch-view': [view: string]
  'auth-event': [event: AuthEvent]
}>()

// Composables
const auth = useAuth(authClient)
const authState = createAuthState()
const { authPaths } = useAuthPaths()

// Provide authState to children
provide('authState', authState)

// Form state
const form = reactive({
  email: '',
  password: ''
})

// Provider config - component reads environment variables directly, no need to pass here
const providerConfig = {}

// Methods
const handleSubmit = async () => {
  // Validate form
  const isValid = authState.validateForm(
    { email: form.email, password: form.password },
    {
      email: authState.validateEmail,
      password: authState.validatePassword
    }
  )

  if (!isValid) return

  authState.setLoading('form')
  authState.clearMessage()

  try {
    const redirectTo = getRedirectParameter()
    const data = await auth.authClient.signInWithPassword({
      email: form.email,
      password: form.password,
      options: redirectTo ? { redirect_to: redirectTo } : undefined
    })

    authState.setSuccessMessage('Successfully signed in!')
    emit('auth-event', { 
      event: 'SIGNED_IN', 
      session: data.session,
      redirect_to: data.redirect_to
    })
  } catch (error: any) {
    authState.setErrorMessage(error.message || 'An unexpected error occurred', error.key)
  } finally {
    authState.clearLoading()
  }
}

const handleAuthEvent = (event: AuthEvent) => {
  emit('auth-event', event)
}
</script>

<style scoped>
.aira-sign-in {
  width: 100%;
}

.aira-sign-in__header {
  text-align: center;
  margin-bottom: 2rem;
}

.aira-sign-in__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-sign-in__form {
  width: 100%;
}

.aira-sign-in__forgot-password,
.aira-sign-in__magic-link {
  text-align: center;
  margin-top: 1rem;
}

.aira-sign-in__footer {
  text-align: center;
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--auth-ui-border);
}
</style>
