<template>
  <div class="aira-email-management">
    <div class="aira-email-management__header">
      <h2 class="aira-email-management__title">
        {{ localization?.title || 'Change Email' }}
      </h2>
    </div>

    <form
      class="aira-email-management__form"
      @submit.prevent="handleSubmit"
      data-testid="email-form"
      :data-status="formState.loading ? 'loading' : 'idle'"
    >
      <Message
        v-if="formState.message"
        :type="formState.messageType"
        :message="formState.message"
        :error-key="formState.messageKey"
        data-testid="email-message"
      />

      <!-- Current Email (Read-only) -->
      <div class="aira-email-management__field" v-if="currentEmail">
        <Label
          :text="localization?.current_email_label || 'Current email'"
          html-for="current-email"
          data-testid="current-email-label"
        />
        <Input
          id="current-email"
          :model-value="currentEmail"
          type="email"
          :disabled="true"
          data-testid="current-email-input"
        />
      </div>

      <!-- New Email -->
      <Input
        v-model="form.newEmail"
        type="email"
        :label="localization?.new_email_label || 'New email address'"
        :placeholder="localization?.new_email_placeholder || 'Enter new email address'"
        :error="formErrors.newEmail"
        :disabled="formState.loading || verificationSent"
        auto-complete="email"
        required
        data-testid="email-new-input"
      />

      <!-- Verification Code (shown after sending) -->
      <Input
        v-if="verificationSent"
        v-model="form.verificationCode"
        type="text"
        :label="localization?.verification_code_label || 'Verification code'"
        :placeholder="localization?.verification_code_placeholder || 'Enter verification code'"
        :error="formErrors.verificationCode"
        :disabled="formState.loading"
        required
        data-testid="email-verification-input"
      />

      <!-- Action Buttons -->
      <div class="aira-email-management__actions">
        <Button
          v-if="!verificationSent"
          type="submit"
          :variant="'primary'"
          :loading="formState.loading"
          :disabled="formState.loading || !form.newEmail"
          :full-width="true"
          data-testid="email-send-code-button"
        >
          {{ localization?.send_code_button_label || 'Send verification code' }}
        </Button>

        <div v-else class="aira-email-management__verify-section">
          <Button
            type="submit"
            :variant="'primary'"
            :loading="formState.loading"
            :disabled="formState.loading || !form.verificationCode"
            :full-width="true"
            data-testid="email-verify-button"
          >
            {{ localization?.verify_button_label || 'Verify email' }}
          </Button>
          
          <Button
            type="button"
            :variant="'outline'"
            :disabled="formState.loading"
            :full-width="true"
            @click="resetForm"
            data-testid="email-cancel-button"
          >
            Cancel
          </Button>
        </div>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, watch } from 'vue'
import { mergeLocalization } from '../../localization'
import type { Localization, AuthEvent } from '../../types'
import { useAuthContext } from '../../composables/useAuthContext'
import Input from '../ui/Input.vue'
import Button from '../ui/Button.vue'
import Label from '../ui/Label.vue'
import Message from '../ui/Message.vue'

interface EmailManagementProps {
  /** Current user email */
  currentEmail?: string
  /** Custom CSS classes */
  className?: string
}

interface FormState {
  loading: boolean
  message?: string
  messageType?: 'success' | 'error' | 'info'
  messageKey?: string
}

interface FormData {
  newEmail: string
  verificationCode: string
}

interface FormErrors {
  newEmail?: string
  verificationCode?: string
}

const props = defineProps<EmailManagementProps>()


const { authClient, localization: contextLocalization } = useAuthContext()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// Form state
const formState = ref<FormState>({
  loading: false
})

const verificationSent = ref(false)

// Form data
const form = reactive<FormData>({
  newEmail: '',
  verificationCode: ''
})

// Form errors
const formErrors = ref<FormErrors>({})

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).email_management
)

// Validate email format
const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

// Handle form submission
const handleSubmit = async () => {
  if (!verificationSent.value) {
    await sendVerificationCode()
  } else {
    await verifyEmail()
  }
}

// Send verification code
const sendVerificationCode = async () => {
  if (!form.newEmail || !validateEmail(form.newEmail)) {
    formErrors.value.newEmail = 'Please enter a valid email address'
    return
  }

  if (form.newEmail === props.currentEmail) {
    formErrors.value.newEmail = 'New email must be different from current email'
    return
  }

  formState.value.loading = true
  formState.value.message = undefined
  formErrors.value = {}

  const result = await authClient.updateEmail({
    email: form.newEmail
  })

  // Show success message
  formState.value.message = localization.value?.code_sent_message || 'Verification code sent to your new email'
  formState.value.messageType = 'info'
  formState.value.loading = false

  // Switch to verification mode
  verificationSent.value = true

  // Emit auth event
  emit('auth-event', {
    event: 'email_verification_sent',
    email: form.newEmail,
    data: result
  })
}

// Verify email change
const verifyEmail = async () => {
  if (!form.verificationCode.trim()) {
    formErrors.value.verificationCode = 'Please enter the verification code'
    return
  }

  formState.value.loading = true
  formState.value.message = undefined
  formErrors.value = {}

  const result = await authClient.verifyEmailChange({
    email: form.newEmail,
    token: form.verificationCode
  })

  // Show success message
  formState.value.message = localization.value?.success_message || 'Email updated successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false

  // Reset form
  resetForm()

  // Emit auth event
  emit('auth-event', {
    event: 'email_updated',
    email: form.newEmail,
    data: result
  })
}

// Reset form
const resetForm = () => {
  form.newEmail = ''
  form.verificationCode = ''
  verificationSent.value = false
  formErrors.value = {}
  formState.value.message = undefined
}

// Watch for form changes to clear errors
const clearErrors = () => {
  if (Object.keys(formErrors.value).length > 0) {
    formErrors.value = {}
  }
}

// Watch form fields for validation
watch(() => [form.newEmail, form.verificationCode], clearErrors)
</script>

<style scoped>
.aira-email-management {
  width: 100%;
  max-width: 28rem;
  margin: 0 auto;
}

.aira-email-management__header {
  margin-bottom: 1.5rem;
}

.aira-email-management__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-email-management__form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-email-management__field {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-email-management__actions {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.aira-email-management__verify-section {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
</style>
