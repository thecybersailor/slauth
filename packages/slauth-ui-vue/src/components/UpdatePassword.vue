<template>
  <div class="aira-update-password">
    <!-- Header Slot -->
    <div v-if="$slots.header" class="aira-update-password__header-slot">
      <slot name="header" :view="'update_password'" />
    </div>
    
    <!-- Default Header -->
    <div v-else class="aira-update-password__header">
      <h2 class="aira-update-password__title">Update your password</h2>
      <p class="aira-update-password__description">
        Enter your new password below.
      </p>
    </div>

    <!-- Password Form -->
    <form
      class="aira-update-password__form"
      @submit.prevent="handleSubmit"
    >
      <Message
        v-if="authState.formState.message"
        :type="authState.formState.messageType"
        :message="authState.formState.message"
      />

      <Input
        v-model="form.password"
        type="password"
        :label="localization?.password_label || 'New password'"
        :placeholder="'Enter new password'"
        :error="authState.getError('password')"
        :disabled="authState.formState.loading"
        auto-complete="new-password"
        required
        data-testid="update-password-input"
      />

      <Input
        v-model="form.confirmPassword"
        type="password"
        label="Confirm Password"
        placeholder="Confirm new password"
        :error="authState.getError('confirmPassword')"
        :disabled="authState.formState.loading"
        auto-complete="new-password"
        required
        data-testid="update-confirm-password-input"
      />

      <Button
        type="submit"
        variant="primary"
        size="md"
        full-width
        :loading="authState.formState.loading"
        data-testid="update-password-button"
      >
        {{ authState.formState.loading ? (localization?.loading_button_label || 'Updating...') : (localization?.button_label || 'Update password') }}
      </Button>
    </form>

    <!-- Footer Slot -->
    <div v-if="$slots.footer" class="aira-update-password__footer-slot">
      <slot name="footer" :view="'update_password'" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue'
import type { AuthEvent, Localization } from '../types'
import { useAuth } from '../composables/useAuth'
import { useAuthState } from '../composables/useAuthState'
import { useAuthContext } from '../composables/useAuthContext'
import Input from './ui/Input.vue'
import Button from './ui/Button.vue'
import Message from './ui/Message.vue'

// Props
interface Props {
  localization: Localization['update_password']
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

// Form state
const form = reactive({
  password: '',
  confirmPassword: ''
})

// Methods
const handleSubmit = async () => {
  // Validate form
  const isValid = authState.validateForm(
    { 
      password: form.password,
      confirmPassword: form.confirmPassword
    },
    {
      password: authState.validatePassword,
      confirmPassword: (value) => authState.validateConfirmPassword(form.password, value)
    }
  )

  if (!isValid) return

  authState.setLoading(true)
  authState.clearMessage()

  try {
    await auth.authClient.updatePassword({ password: form.password })

    authState.setSuccessMessage(props.localization?.confirmation_text || 'Password updated successfully!')
    emit('auth-event', { event: 'PASSWORD_UPDATED' })
  } catch (error) {
    authState.setErrorMessage('An unexpected error occurred')
  } finally {
    authState.setLoading(false)
  }
}
</script>

<style scoped>
.aira-update-password {
  width: 100%;
}

.aira-update-password__header {
  text-align: center;
  margin-bottom: 2rem;
}

.aira-update-password__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0 0 0.5rem 0;
}

.aira-update-password__description {
  color: var(--auth-ui-text-muted);
  margin: 0;
}

.aira-update-password__form {
  width: 100%;
}
</style>
