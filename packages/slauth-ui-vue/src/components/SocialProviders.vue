<template>
  <div v-if="providers && providers.length > 0" class="social-providers" :class="{ 'loading': isLoading }">
    <div 
      v-for="(Provider, index) in resolvedProviders" 
      :key="index"
      class="social-provider"
    >
      <component
        :is="Provider"
        :localization="localization"
        @credential="handleCredential"
        @redirect="handleRedirect"
        @error="handleError"
        @success="handleSuccess"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import type { SocialProvider } from '../types'
import type { AuthEvent, Localization } from '../types'
import { allProviders, getProvider } from '../providers'
import { useAuthContext } from '../composables/useAuthContext'
import { useAuthState } from '../composables/useAuthState'

// Props
interface Props {
  localization?: Localization['sign_in']
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  className: ''
})

// Use AuthContext
const { authClient, authConfig } = useAuthContext()
const providers = computed(() => authConfig.providers || [])

// Inject authState from parent
const authState = useAuthState()
const isLoading = computed(() => authState?.formState?.loading || false)

// Emits
const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// State
const loading = ref(false)

// Computed - handle both string and component cases
const resolvedProviders = computed(() => {
  // If providers is empty, output all components
  if (!providers.value || providers.value.length === 0) {
    return Object.values(allProviders)
  }

  return providers.value.map(provider => {
    if (typeof provider === 'string') {
      // Select component from component library
      return getProvider(provider)
    }
    return provider
  })
})

// Methods
const handleCredential = (credential: any) => {
  // Convert credential to AuthEvent
  emit('auth-event', {
    event: 'AUTH_ID_TOKEN',
    data: { credential }
  })
}

const handleRedirect = (url: string) => {
  emit('auth-event', {
    event: 'AUTH_REDIRECT',
    data: { url }
  })
}

const handleError = (error: any) => {
  emit('auth-event', {
    event: 'AUTH_ERROR',
    error: error.message || 'Authentication failed'
  })
}

const handleSuccess = (data: any) => {
  emit('auth-event', {
    event: 'AUTH_SUCCESS',
    data
  })
}
</script>

<style scoped>
.social-providers {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.social-providers.loading {
  pointer-events: none;
}

.social-provider {
  width: 100%;
}
</style>
