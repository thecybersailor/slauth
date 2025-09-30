<template>
  <div class="aira-phone-management">
    <div class="aira-phone-management__header">
      <h2 class="aira-phone-management__title">
        {{ localization?.title || 'Change Phone Number' }}
      </h2>
    </div>

    <form
      class="aira-phone-management__form"
      @submit.prevent="handleSubmit"
      data-testid="phone-form"
      :data-status="formState.loading ? 'loading' : 'idle'"
    >
      <Message
        v-if="formState.message"
        :type="formState.messageType"
        :message="formState.message"
        :error-key="formState.messageKey"
        data-testid="phone-message"
      />

      <!-- Current Phone (Read-only) -->
      <div class="aira-phone-management__field" v-if="currentPhone">
        <Label
          :text="localization?.current_phone_label || 'Current phone number'"
          html-for="current-phone"
          data-testid="current-phone-label"
        />
        <Input
          id="current-phone"
          :model-value="currentPhone"
          type="tel"
          :disabled="true"
          data-testid="current-phone-input"
        />
      </div>

      <!-- New Phone -->
      <Input
        v-model="form.newPhone"
        type="tel"
        :label="localization?.new_phone_label || 'New phone number'"
        :placeholder="localization?.new_phone_placeholder || 'Enter new phone number'"
        :error="formErrors.newPhone"
        :disabled="formState.loading || verificationSent"
        auto-complete="tel"
        required
        data-testid="phone-new-input"
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
        data-testid="phone-verification-input"
      />

      <!-- Action Buttons -->
      <div class="aira-phone-management__actions">
        <Button
          v-if="!verificationSent"
          type="submit"
          :variant="'primary'"
          :loading="formState.loading"
          :disabled="formState.loading || !form.newPhone"
          :full-width="true"
          data-testid="phone-send-code-button"
        >
          {{ localization?.send_code_button_label || 'Send verification code' }}
        </Button>

        <div v-else class="aira-phone-management__verify-section">
          <Button
            type="submit"
            :variant="'primary'"
            :loading="formState.loading"
            :disabled="formState.loading || !form.verificationCode"
            :full-width="true"
            data-testid="phone-verify-button"
          >
            {{ localization?.verify_button_label || 'Verify phone' }}
          </Button>
          
          <Button
            type="button"
            :variant="'outline'"
            :disabled="formState.loading"
            :full-width="true"
            @click="resetForm"
            data-testid="phone-cancel-button"
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
import { useAuthContext } from '../../composables/useAuthContext'
import { mergeLocalization } from '../../localization'
import type { Localization, AuthEvent } from '../../types'
import Input from '../ui/Input.vue'
import Button from '../ui/Button.vue'
import Label from '../ui/Label.vue'
import Message from '../ui/Message.vue'

interface PhoneManagementProps {
  /** Current user phone */
  currentPhone?: string
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
  newPhone: string
  verificationCode: string
}

interface FormErrors {
  newPhone?: string
  verificationCode?: string
}

const props = defineProps<PhoneManagementProps>()


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
  newPhone: '',
  verificationCode: ''
})

// Form errors
const formErrors = ref<FormErrors>({})

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).phone_management
)

// Validate phone format (basic international format)
const validatePhone = (phone: string): boolean => {
  const phoneRegex = /^\+?[\d\s\-\(\)]{10,}$/
  return phoneRegex.test(phone)
}

// Handle form submission
const handleSubmit = async () => {
  if (!verificationSent.value) {
    await sendVerificationCode()
  } else {
    await verifyPhone()
  }
}

// Send verification code
const sendVerificationCode = async () => {
  if (!form.newPhone || !validatePhone(form.newPhone)) {
    formErrors.value.newPhone = 'Please enter a valid phone number'
    return
  }

  if (form.newPhone === props.currentPhone) {
    formErrors.value.newPhone = 'New phone number must be different from current phone number'
    return
  }

  formState.value.loading = true
  formState.value.message = undefined
  formErrors.value = {}

  const result = await authClient.updatePhone({
    phone: form.newPhone
  })

  // Show success message
  formState.value.message = localization.value?.code_sent_message || 'Verification code sent to your new phone'
  formState.value.messageType = 'info'
  formState.value.loading = false

  // Switch to verification mode
  verificationSent.value = true

  // Emit auth event
  emit('auth-event', {
    event: 'phone_verification_sent',
    phone: form.newPhone,
    data: result
  })
}

// Verify phone change
const verifyPhone = async () => {
  if (!form.verificationCode.trim()) {
    formErrors.value.verificationCode = 'Please enter the verification code'
    return
  }

  formState.value.loading = true
  formState.value.message = undefined
  formErrors.value = {}

  const result = await authClient.verifyPhoneChange({
    phone: form.newPhone,
    token: form.verificationCode
  })

  // Show success message
  formState.value.message = localization.value?.success_message || 'Phone number updated successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false

  // Reset form
  resetForm()

  // Emit auth event
  emit('auth-event', {
    event: 'phone_updated',
    phone: form.newPhone,
    data: result
  })
}

// Reset form
const resetForm = () => {
  form.newPhone = ''
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
watch(() => [form.newPhone, form.verificationCode], clearErrors)
</script>

<style scoped>
.aira-phone-management {
  width: 100%;
  max-width: 28rem;
  margin: 0 auto;
}

.aira-phone-management__header {
  margin-bottom: 1.5rem;
}

.aira-phone-management__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-phone-management__form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-phone-management__field {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-phone-management__actions {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.aira-phone-management__verify-section {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
</style>
