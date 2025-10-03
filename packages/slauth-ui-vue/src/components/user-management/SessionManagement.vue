<template>
  <div class="aira-session-management">
    <div class="aira-session-management__header">
      <h2 class="aira-session-management__title">
        {{ localization?.title || 'Active Sessions' }}
      </h2>
    </div>

    <div class="aira-session-management__content">
      <Message
        v-if="formState.message"
        :type="formState.messageType"
        :message="formState.message"
        :error-key="formState.messageKey"
        data-testid="session-message"
      />

      <!-- Sessions List -->
      <div v-if="sessions.length > 0" class="aira-session-management__sessions">
        <div class="aira-session-management__sessions-header">
          <span class="aira-session-management__sessions-count">
            {{ sessions.length }} active session{{ sessions.length !== 1 ? 's' : '' }}
          </span>
          
          <Button
            :variant="'outline'"
            :size="'sm'"
            :disabled="formState.loading"
            @click="revokeAllSessions"
            data-testid="revoke-all-sessions-button"
          >
            {{ localization?.revoke_all_button_label || 'Revoke all sessions' }}
          </Button>
        </div>

        <div class="aira-session-management__session-list">
          <SessionTable
            :api-sessions="sessions"
            :current-session-id="currentSessionId"
            :loading="formState.loading"
            :localization="localization"
            @revoke="revokeSession"
          />
        </div>
      </div>

      <!-- No Sessions -->
      <div v-else class="aira-session-management__empty">
        <p class="aira-session-management__empty-text">
          No active sessions found.
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { mergeLocalization } from '../../localization'
import type { AuthEvent } from '../../types'
import { useAuthContext } from '../../composables/useAuthContext'
import Button from '../ui/Button.vue'
import Message from '../ui/Message.vue'
import SessionTable from '../ui/SessionTable.vue'

interface ApiSession {
  id: string
  user_id: string
  aal: string
  user_agent: string
  ip: string
  created_at: string
  updated_at: string
  refreshed_at: string
}

interface SessionManagementProps {
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


const props = defineProps<SessionManagementProps>()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// Form state
const formState = ref<FormState>({
  loading: false
})

// Data
const sessions = ref<ApiSession[]>([])
const currentSessionId = ref<string | undefined>(undefined)

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).session_management
)

// Load sessions
const loadSessions = async () => {
  formState.value.loading = true
  
  const result = await authClient.getSessions()
  sessions.value = (result.sessions || []) as ApiSession[]
  
  // Get current session ID
  const currentSession = authClient.getSession()
  currentSessionId.value = currentSession?.id || undefined
  
  formState.value.loading = false
}

// Revoke specific session
const revokeSession = async (sessionId: string) => {
  if (sessionId === currentSessionId.value) {
    formState.value.message = 'Cannot revoke current session'
    formState.value.messageType = 'error'
    return
  }

  formState.value.loading = true
  formState.value.message = undefined

  await authClient.revokeSession(sessionId)

  sessions.value = sessions.value.filter((s: ApiSession) => s.id !== sessionId)

  formState.value.message = localization.value?.revoked_message || 'Session revoked successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false

  emit('auth-event', {
    event: 'session_revoked',
    data: { sessionId }
  })
}

// Revoke all sessions (excluding current session)
const revokeAllSessions = async () => {
  const nonCurrentSessions = sessions.value.filter((s: ApiSession) => s.id !== currentSessionId.value)
  
  if (nonCurrentSessions.length === 0) {
    formState.value.message = 'No other sessions to revoke'
    formState.value.messageType = 'info'
    return
  }

  if (!confirm(`Are you sure you want to revoke ${nonCurrentSessions.length} other session${nonCurrentSessions.length !== 1 ? 's' : ''}? This will log you out of all other devices.`)) {
    return
  }

  formState.value.loading = true
  formState.value.message = undefined

  await authClient.revokeAllSessions(true)

  sessions.value = sessions.value.filter((s: ApiSession) => s.id === currentSessionId.value)

  formState.value.message = localization.value?.all_revoked_message || 'All other sessions revoked successfully'
  formState.value.messageType = 'success'
  formState.value.loading = false

  emit('auth-event', {
    event: 'all_sessions_revoked',
    data: {}
  })
}


// Load sessions on mount
onMounted(() => {
  if (authClient.isAuthenticated()) {
    loadSessions()
  }
})

// Watch for auth state changes
watch(() => authClient.isAuthenticated(), (isAuthenticated) => {
  if (isAuthenticated) {
    loadSessions()
  } else {
    sessions.value = []
  }
})
</script>

<style scoped>
.aira-session-management {
  width: 100%;
  max-width: 64rem;
  margin: 0 auto;
}

.aira-session-management__header {
  margin-bottom: 1.5rem;
}

.aira-session-management__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-session-management__content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.aira-session-management__sessions {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-session-management__sessions-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.aira-session-management__sessions-count {
  font-size: 0.875rem;
  color: var(--auth-ui-text-secondary);
}

.aira-session-management__session-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.aira-session-management__empty {
  text-align: center;
  padding: 2rem 0;
}

.aira-session-management__empty-text {
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}
</style>

