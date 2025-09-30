<template>
  <div class="aira-sign-up">
    <div class="aira-sign-up__header">
      <h2 class="aira-sign-up__title">Create your account</h2>
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
      class="aira-sign-up__form"
      @submit.prevent="handleSubmit"
      data-testid="signup-form"
      :data-status="authState.formState.loading ? 'loading' : 'idle'"
    >
      <Message
        v-if="authState.formState.message"
        :type="authState.formState.messageType"
        :message="authState.formState.message"
      />

      <Input
        v-model="form.email"
        type="email"
        :label="localization?.email_label || 'Email address'"
        :placeholder="'Enter your email'"
        :error="authState.getError('email')"
        :disabled="authState.formState.loading"
        auto-complete="email"
        required
        data-testid="signup-email-input"
      />

      <Input
        v-model="form.password"
        type="password"
        :label="localization?.password_label || 'Password'"
        :placeholder="'Create a password'"
        :error="authState.getError('password')"
        :disabled="authState.formState.loading"
        auto-complete="new-password"
        required
        data-testid="signup-password-input"
      />

      <Input
        v-model="form.confirmPassword"
        type="password"
        label="Confirm Password"
        placeholder="Confirm your password"
        :error="authState.getError('confirmPassword')"
        :disabled="authState.formState.loading"
        auto-complete="new-password"
        required
        data-testid="signup-confirm-password-input"
      />

      <Button
        type="submit"
        variant="primary"
        size="md"
        full-width
        :loading="authState.formState.loading"
        data-testid="signup-button"
      >
        {{ authState.formState.loading ? (localization?.loading_button_label || 'Creating account...') : (localization?.button_label || 'Sign up') }}
      </Button>
    </form>

    <!-- Sign In Link -->
    <div
      v-if="showLinks"
      class="aira-sign-up__footer"
    >
      <Anchor
        :href="authPaths.signin"
        :text="localization?.link_text || 'Already have an account? Sign in'"
        data-testid="signin-redirect-link"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, computed } from 'vue'
import type { AuthEvent, Localization } from '../types'
import { useAuth } from '../composables/useAuth'
import { useAuthState } from '../composables/useAuthState'
import { useAuthPaths } from '../composables/useAuthPaths'
import { useAuthContext } from '../composables/useAuthContext'
import Input from './ui/Input.vue'
import Button from './ui/Button.vue'
import Message from './ui/Message.vue'
import Divider from './ui/Divider.vue'
import Anchor from './ui/Anchor.vue'
import SocialProviders from './SocialProviders.vue'

// Props
interface Props {
  localization: Localization['sign_up']
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
const onlyThirdPartyProviders = computed(() => authConfig.onlyThirdPartyProviders || false)
const redirectTo = computed(() => authConfig.redirectTo)

// Emits
const emit = defineEmits<{
  'switch-view': [view: string]
  'auth-event': [event: AuthEvent]
}>()

// Composables
const auth = useAuth(authClient)
const authState = useAuthState()
const { authPaths } = useAuthPaths()

// Form state
const form = reactive({
  email: '',
  password: '',
  confirmPassword: ''
})

// Provider config - component reads environment variables directly, no need to pass here
const providerConfig = {}

// Methods
const handleSubmit = async () => {
  // Validate form
  const isValid = authState.validateForm(
    { 
      email: form.email, 
      password: form.password,
      confirmPassword: form.confirmPassword
    },
    {
      email: authState.validateEmail,
      password: authState.validatePassword,
      confirmPassword: (value) => authState.validateConfirmPassword(form.password, value)
    }
  )

  if (!isValid) return

  authState.setLoading(true)
  authState.clearMessage()

  try {
    const data = await auth.authClient.signUp({ email: form.email, password: form.password })

    // Registration successful
    authState.setSuccessMessage('Account created successfully! Please check your email for verification.')
    emit('auth-event', { event: 'SIGNED_UP', session: data.session })
  } catch (error: any) {
    // Handle error
    if (error && error.message) {
      authState.setErrorMessage(error.message, error.key)
    } else {
      authState.setErrorMessage('An unexpected error occurred')
    }
  } finally {
    authState.setLoading(false)
  }
}

const handleAuthEvent = (event: AuthEvent) => {
  emit('auth-event', event)
}
</script>

<style scoped>
.aira-sign-up {
  width: 100%;
}

.aira-sign-up__header {
  text-align: center;
  margin-bottom: 2rem;
}

.aira-sign-up__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-sign-up__form {
  width: 100%;
}

.aira-sign-up__footer {
  text-align: center;
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--auth-ui-border);
}
</style>
