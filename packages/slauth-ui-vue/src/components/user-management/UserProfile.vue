<template>
  <div class="aira-user-profile">
    <div class="aira-user-profile__header">
      <h2 class="aira-user-profile__title">
        {{ localization?.title || 'Profile' }}
      </h2>
    </div>

    <form
      class="aira-user-profile__form"
      @submit.prevent="handleSubmit"
      data-testid="user-profile-form"
      :data-status="formState.loading ? 'loading' : 'idle'"
    >
      <Message
        v-if="formState.message"
        :type="formState.messageType"
        :message="formState.message"
        :error-key="formState.messageKey"
        data-testid="profile-message"
      />

      <!-- Email Field (Read-only) -->
      <div class="aira-user-profile__field" v-if="user?.email">
        <Label
          :text="localization?.email_label || 'Email address'"
          html-for="profile-email"
          data-testid="profile-email-label"
        />
        <Input
          id="profile-email"
          :model-value="user.email"
          type="email"
          :disabled="true"
          data-testid="profile-email-input"
        />
        <div class="aira-user-profile__field-note">
          To change your email, use the email management section.
        </div>
      </div>

      <!-- Phone Field (Read-only) -->
      <div class="aira-user-profile__field" v-if="user?.phone">
        <Label
          :text="localization?.phone_label || 'Phone number'"
          html-for="profile-phone"
          data-testid="profile-phone-label"
        />
        <Input
          id="profile-phone"
          :model-value="user.phone"
          type="tel"
          :disabled="true"
          data-testid="profile-phone-input"
        />
        <div class="aira-user-profile__field-note">
          To change your phone number, use the phone management section.
        </div>
      </div>

      <!-- User Metadata (Editable) -->
      <div class="aira-user-profile__field" v-if="showMetadata">
        <Label
          :text="localization?.metadata_label || 'Additional information'"
          html-for="profile-metadata"
          data-testid="profile-metadata-label"
        />
        <textarea
          id="profile-metadata"
          v-model="metadataJson"
          class="aira-user-profile__metadata-input"
          :placeholder="'Enter additional information (JSON format)'"
          :disabled="formState.loading"
          rows="4"
          data-testid="profile-metadata-input"
        />
        <div class="aira-user-profile__field-note">
          Enter valid JSON format for additional user information.
        </div>
      </div>

      <!-- Save Button -->
      <Button
        type="submit"
        :variant="'primary'"
        :loading="formState.loading"
        :disabled="formState.loading"
        :full-width="true"
        data-testid="profile-save-button"
      >
        {{ formState.loading 
          ? (localization?.loading_button_label || 'Saving ...')
          : (localization?.save_button_label || 'Save changes')
        }}
      </Button>
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { mergeLocalization, formatError } from '../../localization'
import type { Localization, AuthEvent } from '../../types'
import { useAuthContext } from '../../composables/useAuthContext'
import Input from '../ui/Input.vue'
import Button from '../ui/Button.vue'
import Label from '../ui/Label.vue'
import Message from '../ui/Message.vue'

interface UserProfileProps {
  /** Show metadata editing */
  showMetadata?: boolean
  /** Custom CSS classes */
  className?: string
}

interface FormState {
  loading: boolean
  message?: string
  messageType?: 'success' | 'error' | 'info'
  messageKey?: string
}

const props = withDefaults(defineProps<UserProfileProps>(), {
  showMetadata: true
})


const { authClient, localization: contextLocalization } = useAuthContext()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// Form state
const formState = ref<FormState>({
  loading: false
})

// User data
const user = ref<any>(null)
const metadataJson = ref('')

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).user_profile
)

// Load user data
const loadUser = async () => {
  formState.value.loading = true
  formState.value.message = undefined
  
  const result = await authClient.getUser()
  user.value = result.user
  
  // Initialize metadata JSON
  if (result.user?.user_metadata) {
    metadataJson.value = JSON.stringify(result.user.user_metadata, null, 2)
  }
  
  formState.value.loading = false
}

// Handle form submission
const handleSubmit = async () => {
  if (!user.value) return
  
  formState.value.loading = true
  formState.value.message = undefined
  
  const updates: any = {}
  
  // Parse and validate metadata JSON
  if (props.showMetadata && metadataJson.value.trim()) {
    try {
      updates.user_metadata = JSON.parse(metadataJson.value)
    } catch (error) {
      formState.value.message = 'Invalid JSON format for additional information'
      formState.value.messageType = 'error'
      formState.value.loading = false
      return
    }
  }
  
  // Only submit if there are updates
  if (Object.keys(updates).length === 0) {
    formState.value.loading = false
    return
  }
  
  const result = await authClient.updateUser(updates)
  
  // Update local user data
  user.value = result.user
  
  // Show success message
  formState.value.message = localization.value?.success_message || 'Profile updated successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false
  
  // Emit auth event
  emit('auth-event', {
    event: 'profile_updated',
    session: authClient.getSession(),
    data: result
  })
}

// Watch for auth state changes
watch(() => authClient.isAuthenticated(), (isAuthenticated) => {
  if (isAuthenticated) {
    loadUser()
  } else {
    user.value = null
  }
}, { immediate: true })

// Initialize on mount
onMounted(() => {
  if (authClient.isAuthenticated()) {
    loadUser()
  }
})
</script>

<style scoped>
.aira-user-profile {
  width: 100%;
  max-width: 28rem;
  margin: 0 auto;
}

.aira-user-profile__header {
  margin-bottom: 1.5rem;
}

.aira-user-profile__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-user-profile__form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-user-profile__field {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-user-profile__field-note {
  font-size: 0.875rem;
  color: var(--auth-ui-text-tertiary);
}

.aira-user-profile__metadata-input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--auth-ui-input-border);
  border-radius: 0.375rem;
  box-shadow: var(--auth-ui-shadow-sm);
  background-color: var(--auth-ui-input-background);
  color: var(--auth-ui-input-text);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 0.875rem;
  outline: none;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.aira-user-profile__metadata-input::placeholder {
  color: var(--auth-ui-input-placeholder);
}

.aira-user-profile__metadata-input:focus {
  border-color: var(--auth-ui-input-border-focus);
  box-shadow: 0 0 0 2px var(--auth-ui-primary);
}

.aira-user-profile__metadata-input:disabled {
  background-color: var(--auth-ui-background-tertiary);
  color: var(--auth-ui-text-quaternary);
  cursor: not-allowed;
}
</style>
