<template>
  <div class="aira-verify-otp">
    <!-- Header Slot -->
    <div v-if="$slots.header" class="aira-verify-otp__header-slot">
      <slot name="header" :view="'verify_otp'" />
    </div>
    
    <!-- Default Header -->
    <div v-else class="aira-verify-otp__header">
      <h2 class="aira-verify-otp__title">Verify your email</h2>
      <p class="aira-verify-otp__description">
        Enter the verification code sent to your email.
      </p>
    </div>

    <!-- OTP Form -->
    <form
      class="aira-verify-otp__form"
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
        data-testid="verify-otp-email-input"
      />

      <Input
        v-model="form.token"
        type="text"
        :label="localization?.token_label || 'Verification code'"
        :placeholder="'Enter verification code'"
        :error="authState.getError('token')"
        :disabled="authState.formState.loading"
        auto-complete="one-time-code"
        required
        data-testid="verification-code-input"
      />

      <Button
        type="submit"
        variant="primary"
        size="md"
        full-width
        :loading="authState.formState.loading"
        data-testid="verify-button"
      >
        {{ authState.formState.loading ? (localization?.loading_button_label || 'Verifying...') : (localization?.button_label || 'Verify') }}
      </Button>
    </form>

    <!-- Resend Code Button -->
    <div class="aira-verify-otp__resend">
      <Button
        variant="secondary"
        size="sm"
        :loading="resendLoading"
        :disabled="resendCooldown > 0"
        @click="handleResend"
        data-testid="resend-button"
        :data-status="resendLoading ? 'loading' : 'idle'"
      >
        {{ resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend verification code' }}
      </Button>
    </div>

    <!-- Footer Slot -->
    <div v-if="$slots.footer" class="aira-verify-otp__footer-slot">
      <slot name="footer" :view="'verify_otp'" />
    </div>
    
    <!-- Default Footer -->
    <div v-else class="aira-verify-otp__footer">
      <Anchor
        :href="authPaths.signin"
        text="Back to sign in"
        data-testid="back-to-signin-link"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
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
  localization: Localization['verify_otp']
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  className: ''
})


const { authClient } = useAuthContext()

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
  token: ''
})

// Resend state
const resendLoading = ref(false)
const resendCooldown = ref(0)
let resendTimer: number | null = null

// Methods
const handleSubmit = async () => {
  // Validate form
  const isValid = authState.validateForm(
    { 
      email: form.email,
      token: form.token
    },
    {
      email: authState.validateEmail,
      token: authState.validateToken
    }
  )

  if (!isValid) return

  authState.setLoading(true)
  authState.clearMessage()

  try {
    const authData = await auth.authClient.verifyOtp({
      email: form.email,
      token: form.token,
      type: 'email'
    })

    authState.setSuccessMessage('Email verified successfully!')
    emit('auth-event', { event: 'SIGNED_IN', session: authData.session })
  } catch (error) {
    authState.setErrorMessage('An unexpected error occurred')
  } finally {
    authState.setLoading(false)
  }
}

// Resend verification code
const handleResend = async () => {
  if (resendLoading.value || resendCooldown.value > 0) return

  resendLoading.value = true
  authState.clearMessage()

  // Add a small delay to ensure loading state is visible
  await new Promise(resolve => setTimeout(resolve, 100))

  try {
    await auth.authClient.resend({
      type: 'signup',
      email: form.email
    })
    
    authState.setSuccessMessage('Verification code sent!')
    startResendCooldown()
  } catch (error) {
    authState.setErrorMessage('Failed to resend verification code')
  } finally {
    resendLoading.value = false
  }
}

// Start resend cooldown timer
const startResendCooldown = () => {
  resendCooldown.value = 60 // 60 seconds cooldown
  
  resendTimer = setInterval(() => {
    resendCooldown.value--
    if (resendCooldown.value <= 0) {
      clearInterval(resendTimer!)
      resendTimer = null
    }
  }, 1000)
}

// Cleanup timer on unmount
import { onUnmounted } from 'vue'
onUnmounted(() => {
  if (resendTimer) {
    clearInterval(resendTimer)
  }
})
</script>

<style scoped>
.aira-verify-otp {
  width: 100%;
}

.aira-verify-otp__header {
  text-align: center;
  margin-bottom: 2rem;
}

.aira-verify-otp__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0 0 0.5rem 0;
}

.aira-verify-otp__description {
  color: var(--auth-ui-text-muted);
  margin: 0;
}

.aira-verify-otp__form {
  width: 100%;
}

.aira-verify-otp__resend {
  text-align: center;
  margin-top: 1rem;
}

.aira-verify-otp__footer {
  text-align: center;
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--auth-ui-border);
}
</style>
