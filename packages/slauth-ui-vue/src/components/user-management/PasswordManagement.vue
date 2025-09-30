<template>
  <div class="aira-password-management">
    <div class="aira-password-management__header">
      <h2 class="aira-password-management__title">
        {{ localization?.title || 'Change Password' }}
      </h2>
    </div>

    <form
      class="aira-password-management__form"
      @submit.prevent="handleSubmit"
      data-testid="password-form"
      :data-status="formState.loading ? 'loading' : 'idle'"
    >
      <Message
        v-if="formState.message"
        :type="formState.messageType"
        :message="formState.message"
        :error-key="formState.messageKey"
        data-testid="password-message"
      />

      <!-- New Password -->
      <Input
        v-model="form.newPassword"
        type="password"
        :label="localization?.new_password_label || 'New password'"
        :placeholder="localization?.new_password_placeholder || 'Enter new password'"
        :error="formErrors.newPassword"
        :disabled="formState.loading"
        auto-complete="new-password"
        required
        data-testid="password-new-input"
      />

      <!-- Confirm Password -->
      <Input
        v-model="form.confirmPassword"
        type="password"
        :label="localization?.confirm_password_label || 'Confirm new password'"
        :placeholder="localization?.confirm_password_placeholder || 'Confirm new password'"
        :error="formErrors.confirmPassword"
        :disabled="formState.loading"
        auto-complete="new-password"
        required
        data-testid="password-confirm-input"
      />

      <!-- Submit Button -->
      <Button
        type="submit"
        :variant="'primary'"
        :loading="formState.loading"
        :disabled="formState.loading || !isFormValid"
        :full-width="true"
        data-testid="password-submit-button"
      >
        {{ formState.loading 
          ? (localization?.loading_button_label || 'Updating password ...')
          : (localization?.save_button_label || 'Update password')
        }}
      </Button>
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
import Message from '../ui/Message.vue'

interface PasswordManagementProps {
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
  newPassword: string
  confirmPassword: string
}

interface FormErrors {
  newPassword?: string
  confirmPassword?: string
}

const props = defineProps<PasswordManagementProps>()


const { authClient, localization: contextLocalization } = useAuthContext()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// Form state
const formState = ref<FormState>({
  loading: false
})

// Form data
const form = reactive<FormData>({
  newPassword: '',
  confirmPassword: ''
})

// Form errors
const formErrors = ref<FormErrors>({})

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).password_management
)

// Form validation
const isFormValid = computed(() => {
  return form.newPassword.length >= 6 && 
         form.confirmPassword.length >= 6 &&
         form.newPassword === form.confirmPassword &&
         !formState.value.loading
})

// Validate form
const validateForm = () => {
  const errors: FormErrors = {}
  
  if (form.newPassword.length < 6) {
    errors.newPassword = 'Password must be at least 6 characters long'
  }
  
  if (form.confirmPassword.length < 6) {
    errors.confirmPassword = 'Password must be at least 6 characters long'
  }
  
  if (form.newPassword !== form.confirmPassword) {
    errors.confirmPassword = 'Passwords do not match'
  }
  
  formErrors.value = errors
  return Object.keys(errors).length === 0
}

// Handle form submission
const handleSubmit = async () => {
  if (!validateForm()) return
  
  formState.value.loading = true
  formState.value.message = undefined
  formErrors.value = {}
  
  const result = await authClient.updatePassword({
    password: form.newPassword
  })
  
  // Show success message
  formState.value.message = localization.value?.success_message || 'Password updated successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false
  
  // Clear form
  form.newPassword = ''
  form.confirmPassword = ''
  
  // Emit auth event
  emit('auth-event', {
    event: 'password_updated',
    session: authClient.getSession(),
    data: result
  })
}

// Watch for form changes to clear errors
const clearErrors = () => {
  if (Object.keys(formErrors.value).length > 0) {
    formErrors.value = {}
  }
}

// Watch form fields for validation
watch(() => [form.newPassword, form.confirmPassword], clearErrors)
</script>

<style scoped>
.aira-password-management {
  width: 100%;
  max-width: 28rem;
  margin: 0 auto;
}

.aira-password-management__header {
  margin-bottom: 1.5rem;
}

.aira-password-management__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-password-management__form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
</style>
