<template>
  <div class="aira-magic-link">
    <!-- Header Slot -->
    <div v-if="$slots.header" class="aira-magic-link__header-slot">
      <slot name="header" :view="'magic_link'" />
    </div>
    
    <!-- Default Header -->
    <div v-else class="aira-magic-link__header">
      <h2 class="aira-magic-link__title">Sign in with magic link</h2>
      <p class="aira-magic-link__description">
        Enter your email and we'll send you a magic link to sign in.
      </p>
    </div>

    <!-- Email Form -->
    <form
      class="aira-magic-link__form"
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
        data-testid="magic-link-email-input"
      />

      <Button
        type="submit"
        variant="primary"
        size="md"
        full-width
        :loading="authState.formState.loading"
        data-testid="magic-link-button"
      >
        {{ authState.formState.loading ? (localization?.loading_button_label || 'Sending...') : (localization?.button_label || 'Send magic link') }}
      </Button>
    </form>

    <!-- Footer Slot -->
    <div v-if="$slots.footer" class="aira-magic-link__footer-slot">
      <slot name="footer" :view="'magic_link'" />
    </div>
    
    <!-- Default Footer -->
    <div
      v-else-if="showLinks"
      class="aira-magic-link__footer"
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
import { createAuthState } from '../composables/useAuthState'
import { useAuthPaths } from '../composables/useAuthPaths'
import { useAuthContext } from '../composables/useAuthContext'
import Input from './ui/Input.vue'
import Button from './ui/Button.vue'
import Message from './ui/Message.vue'
import Anchor from './ui/Anchor.vue'

// Props
interface Props {
  localization: Localization['magic_link']
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
const authState = createAuthState()
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

  authState.setLoading('form')
  authState.clearMessage()

  try {
    await auth.authClient.signInWithOtp({
      email: form.email,
      options: {
        emailRedirectTo: redirectTo.value
      }
    })

    authState.setSuccessMessage(props.localization?.confirmation_text || 'Check your email for the magic link!')
    emit('auth-event', { event: 'MAGIC_LINK_SENT', email: form.email })
  } catch (error) {
    authState.setErrorMessage('An unexpected error occurred')
  } finally {
    authState.clearLoading()
  }
}
</script>

<style scoped>
.aira-magic-link {
  width: 100%;
}

.aira-magic-link__header {
  text-align: center;
  margin-bottom: 2rem;
}

.aira-magic-link__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0 0 0.5rem 0;
}

.aira-magic-link__description {
  color: var(--auth-ui-text-muted);
  margin: 0;
}

.aira-magic-link__form {
  width: 100%;
}

.aira-magic-link__footer {
  text-align: center;
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--auth-ui-border);
}
</style>
