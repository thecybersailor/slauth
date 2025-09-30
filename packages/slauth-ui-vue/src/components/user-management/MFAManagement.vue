<template>
  <div class="aira-mfa-management">
    <div class="aira-mfa-management__header">
      <h2 class="aira-mfa-management__title">
        {{ localization?.title || 'Two-Factor Authentication' }}
      </h2>
    </div>

    <div class="aira-mfa-management__content">
      <!-- Current MFA Factors -->
      <div class="aira-mfa-management__factors" v-if="factors.length > 0">
        <h3 class="aira-mfa-management__subtitle">Current 2FA Methods</h3>
        
        <div class="aira-mfa-management__factor-list">
          <div
            v-for="factor in factors"
            :key="factor.id"
            class="aira-mfa-management__factor"
            data-testid="mfa-factor"
            :data-factor-id="factor.id"
          >
            <div class="aira-mfa-management__factor-info">
              <div class="aira-mfa-management__factor-name">
                {{ factor.friendly_name || factor.type }}
              </div>
              <div class="aira-mfa-management__factor-type">
                {{ factor.type?.toUpperCase() }}
              </div>
              <div class="aira-mfa-management__factor-status">
                Status: {{ factor.status }}
              </div>
            </div>
            
            <Button
              :variant="'outline'"
              :size="'sm'"
              :disabled="formState.loading"
              @click="removeFactor(factor.id)"
              data-testid="mfa-remove-button"
            >
              {{ localization?.remove_button_label || 'Remove' }}
            </Button>
          </div>
        </div>
      </div>

      <!-- No MFA Factors -->
      <div v-else class="aira-mfa-management__empty">
        <p class="aira-mfa-management__empty-text">
          No two-factor authentication methods configured.
        </p>
      </div>

      <!-- Enroll New Factor -->
      <div class="aira-mfa-management__enroll">
        <h3 class="aira-mfa-management__subtitle">Add New Method</h3>
        
        <form
          class="aira-mfa-management__enroll-form"
          @submit.prevent="enrollFactor"
          data-testid="mfa-enroll-form"
          :data-status="formState.loading ? 'loading' : 'idle'"
        >
          <Message
            v-if="formState.message"
            :type="formState.messageType"
            :message="formState.message"
            :error-key="formState.messageKey"
            data-testid="mfa-message"
          />

          <!-- Factor Type Selection -->
          <div class="aira-mfa-management__field">
            <Label
              text="Authentication Method"
              html-for="factor-type"
              data-testid="factor-type-label"
            />
            <select
              id="factor-type"
              v-model="enrollForm.factorType"
              :disabled="formState.loading"
              class="aira-mfa-management__select"
              data-testid="factor-type-select"
            >
              <option value="totp">Authenticator App (TOTP)</option>
              <option value="phone">SMS Verification</option>
            </select>
          </div>

          <!-- Friendly Name -->
          <Input
            v-model="enrollForm.friendlyName"
            type="text"
            label="Device Name"
            placeholder="e.g., My iPhone"
            :disabled="formState.loading"
            required
            data-testid="factor-friendly-name-input"
          />

          <!-- Phone Number (for phone factors) -->
          <Input
            v-if="enrollForm.factorType === 'phone'"
            v-model="enrollForm.phone"
            type="tel"
            label="Phone Number"
            placeholder="+1234567890"
            :disabled="formState.loading"
            required
            data-testid="factor-phone-input"
          />

          <!-- Enroll Button -->
          <Button
            type="submit"
            :variant="'primary'"
            :loading="formState.loading"
            :disabled="formState.loading || !isEnrollFormValid"
            :full-width="true"
            data-testid="mfa-enroll-button"
          >
            {{ localization?.enroll_button_label || 'Set up 2FA' }}
          </Button>
        </form>
      </div>

      <!-- QR Code Display (shown after enrollment) -->
      <div v-if="qrCodeData" class="aira-mfa-management__qr-section">
        <h3 class="aira-mfa-management__subtitle">Complete Setup</h3>
        
        <div class="aira-mfa-management__qr-content">
          <div class="aira-mfa-management__qr-instructions">
            <p class="aira-mfa-management__qr-text">
              {{ localization?.qr_code_label || 'Scan this QR code with your authenticator app' }}
            </p>
          </div>
          
          <div class="aira-mfa-management__qr-code">
            <img :src="qrCodeData?.qr_code" alt="QR Code" data-testid="mfa-qr-code" />
          </div>
          
          <div class="aira-mfa-management__manual-entry">
            <Label
              text="Manual Entry Key"
              html-for="manual-key"
              data-testid="manual-key-label"
            />
            <Input
              :model-value="qrCodeData?.secret"
              type="text"
              :disabled="true"
              data-testid="manual-key-input"
            />
          </div>
          
          <form @submit.prevent="verifyFactor" class="aira-mfa-management__verify-form">
            <Input
              v-model="verificationCode"
              type="text"
              :label="localization?.verify_button_label || 'Verification Code'"
              placeholder="Enter 6-digit code"
              :disabled="formState.loading"
              required
              data-testid="mfa-verify-input"
            />
            
            <Button
              type="submit"
              :variant="'primary'"
              :loading="formState.loading"
              :disabled="formState.loading || !verificationCode"
              :full-width="true"
              data-testid="mfa-verify-button"
            >
              {{ localization?.verify_button_label || 'Verify' }}
            </Button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted, watch } from 'vue'
import type { Types } from '@cybersailor/slauth-ts'
import { mergeLocalization } from '../../localization'
import type { Localization, AuthEvent } from '../../types'
import { useAuthContext } from '../../composables/useAuthContext'
import Input from '../ui/Input.vue'
import Button from '../ui/Button.vue'
import Label from '../ui/Label.vue'
import Message from '../ui/Message.vue'

interface MFAManagementProps {
  /** Custom CSS classes */
  className?: string
}


const { authClient, localization: contextLocalization } = useAuthContext()

interface FormState {
  loading: boolean
  message?: string
  messageType?: 'success' | 'error' | 'info'
  messageKey?: string
}

interface EnrollForm {
  factorType: string
  friendlyName: string
  phone: string
}

const props = defineProps<MFAManagementProps>()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// Form state
const formState = ref<FormState>({
  loading: false
})

// Data
const factors = ref<any[]>([])
const qrCodeData = ref<any>(null)
const verificationCode = ref('')
const currentFactorId = ref('')

// Enroll form
const enrollForm = reactive<EnrollForm>({
  factorType: 'totp',
  friendlyName: '',
  phone: ''
})

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).mfa_management
)

// Form validation
const isEnrollFormValid = computed(() => {
  const hasName = enrollForm.friendlyName.trim().length > 0
  const hasPhone = enrollForm.factorType !== 'phone' || enrollForm.phone.trim().length > 0
  return hasName && hasPhone && !formState.value.loading
})

// Load MFA factors
const loadFactors = async () => {
  formState.value.loading = true
  
  const result = await authClient.listMFAFactors()
  factors.value = result.all || []
  
  formState.value.loading = false
}

// Enroll new factor
const enrollFactor = async () => {
  formState.value.loading = true
  formState.value.message = undefined

  const enrollData: any = {
    factorType: enrollForm.factorType,
    friendlyName: enrollForm.friendlyName
  }

  if (enrollForm.factorType === 'phone') {
    enrollData.phone = enrollForm.phone
  }

  const result = await authClient.enrollMFAFactor(enrollData)
  
  // Store enrollment data for verification
  if (result.totp) {
    qrCodeData.value = result.totp
    currentFactorId.value = result.id || ''
  }
  
  formState.value.message = 'Please scan the QR code and enter the verification code'
  formState.value.messageType = 'info'
  formState.value.loading = false

  // Emit auth event
  emit('auth-event', {
    event: 'mfa_enrollment_started',
    data: result
  })
}

// Verify factor
const verifyFactor = async () => {
  if (!verificationCode.value.trim()) return

  formState.value.loading = true
  formState.value.message = undefined

  const result = await authClient.verifyMFAFactor({
    factorId: currentFactorId.value,
    challengeId: '', // This might need to be handled differently based on API
    code: verificationCode.value
  })

  // Clear verification form
  qrCodeData.value = null
  verificationCode.value = ''
  currentFactorId.value = ''
  
  // Reset enroll form
  enrollForm.friendlyName = ''
  enrollForm.phone = ''

  // Reload factors
  await loadFactors()

  // Show success message
  formState.value.message = localization.value?.success_message || '2FA enabled successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false

  // Emit auth event
  emit('auth-event', {
    event: 'mfa_enrolled',
    data: result
  })
}

// Remove factor
const removeFactor = async (factorId: string) => {
  formState.value.loading = true
  formState.value.message = undefined

  await authClient.unenrollMFAFactor(factorId)

  // Reload factors
  await loadFactors()

  // Show success message
  formState.value.message = localization.value?.removed_message || '2FA disabled successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false

  // Emit auth event
  emit('auth-event', {
    event: 'mfa_unenrolled',
    data: { factorId }
  })
}

// Load factors on mount
onMounted(() => {
  if (authClient.isAuthenticated()) {
    loadFactors()
  }
})

// Watch for auth state changes
watch(() => authClient.isAuthenticated(), (isAuthenticated) => {
  if (isAuthenticated) {
    loadFactors()
  } else {
    factors.value = []
  }
})
</script>

<style scoped>
.aira-mfa-management {
  width: 100%;
  max-width: 48rem;
  margin: 0 auto;
}

.aira-mfa-management__header {
  margin-bottom: 1.5rem;
}

.aira-mfa-management__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-mfa-management__content {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.aira-mfa-management__subtitle {
  font-size: 1.125rem;
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0 0 1rem 0;
}

.aira-mfa-management__factors {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-mfa-management__factor-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.aira-mfa-management__factor {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
  background-color: var(--auth-ui-background);
}

.aira-mfa-management__factor-info {
  flex: 1;
}

.aira-mfa-management__factor-name {
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-mfa-management__factor-type {
  font-size: 0.875rem;
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.aira-mfa-management__factor-status {
  font-size: 0.875rem;
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.aira-mfa-management__empty {
  text-align: center;
  padding: 2rem 0;
}

.aira-mfa-management__empty-text {
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.aira-mfa-management__enroll {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-mfa-management__enroll-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-mfa-management__field {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-mfa-management__select {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--auth-ui-input-border);
  border-radius: 0.375rem;
  box-shadow: var(--auth-ui-shadow-sm);
  background-color: var(--auth-ui-input-background);
  color: var(--auth-ui-input-text);
  outline: none;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.aira-mfa-management__select:focus {
  border-color: var(--auth-ui-input-border-focus);
  box-shadow: 0 0 0 2px var(--auth-ui-primary);
}

.aira-mfa-management__select:disabled {
  background-color: var(--auth-ui-background-tertiary);
  color: var(--auth-ui-text-quaternary);
  cursor: not-allowed;
}

.aira-mfa-management__qr-section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-mfa-management__qr-content {
  text-align: center;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.aira-mfa-management__qr-instructions {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-mfa-management__qr-text {
  color: var(--auth-ui-text-secondary);
  margin: 0;
}

.aira-mfa-management__qr-code {
  display: flex;
  justify-content: center;
}

.aira-mfa-management__qr-code img {
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
}

.aira-mfa-management__manual-entry {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-mfa-management__verify-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
</style>
