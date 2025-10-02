<template>
  <div class="aira-forgot-password">
    <!-- Header Slot -->
    <div v-if="$slots.header" class="aira-forgot-password__header-slot">
      <slot name="header" :view="'forgotten_password'" />
    </div>
    
    <!-- Default Header -->
    <div v-else class="aira-forgot-password__header">
      <h2 class="aira-forgot-password__title">Reset your password</h2>
      <p class="aira-forgot-password__description">
        Enter your email and we'll send you a link to reset your password.
      </p>
    </div>

    <!-- Email Form -->
    <form
      class="aira-forgot-password__form"
      data-testid="forgot-password-form"
      @submit.prevent="handleSubmit"
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
        data-testid="forgot-password-email-input"
      />

      <Button
        type="submit"
        variant="primary"
        size="md"
        full-width
        :loading="authState.formState.loading"
        data-testid="forgot-password-button"
      >
        {{ authState.formState.loading ? (localization?.loading_button_label || 'Sending...') : (localization?.button_label || 'Send reset instructions') }}
      </Button>
    </form>

    <!-- Footer Slot -->
    <div v-if="$slots.footer" class="aira-forgot-password__footer-slot">
      <slot name="footer" :view="'forgotten_password'" />
    </div>
    
    <!-- Default Footer -->
    <div
      v-else-if="showLinks"
      class="aira-forgot-password__footer"
    >
      <Anchor
        :href="authPaths.signin"
        text="Back to sign in"
        data-testid="back-to-signin-link"
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
import Anchor from './ui/Anchor.vue'

// Props
interface Props {
  localization: Localization['forgotten_password']
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  className: ''
})


const { authClient, authConfig } = useAuthContext()
const showLinks = computed(() => authConfig.showLinks !== false)
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
  email: ''
})

// Methods
const handleSubmit = async () => {
  // Validate form
  const isValid = authState.validateForm(
    { email: form.email },
    {
      email: authState.validateEmail
    }
  )

  if (!isValid) return

  authState.setLoading(true)
  authState.clearMessage()

  try {
    await auth.authClient.resetPasswordForEmail(form.email, {
      redirect_to: redirectTo.value
    })

    authState.setSuccessMessage(props.localization?.confirmation_text || 'Check your email for the password reset link!')
    emit('auth-event', { event: 'PASSWORD_RECOVERY', email: form.email })
  } catch (error) {
    authState.setErrorMessage('An unexpected error occurred')
  } finally {
    authState.setLoading(false)
  }
}
</script>

<style scoped>
.aira-forgot-password {
  width: 100%;
}

.aira-forgot-password__header {
  text-align: center;
  margin-bottom: 2rem;
}

.aira-forgot-password__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0 0 0.5rem 0;
}

.aira-forgot-password__description {
  color: var(--auth-ui-text-muted);
  margin: 0;
}

.aira-forgot-password__form {
  width: 100%;
}

.aira-forgot-password__footer {
  text-align: center;
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--auth-ui-border);
}
</style>
