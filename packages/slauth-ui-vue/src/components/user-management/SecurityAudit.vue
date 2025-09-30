<template>
  <div class="aira-security-audit">
    <div class="aira-security-audit__header">
      <h2 class="aira-security-audit__title">
        {{ localization?.title || 'Security & Audit' }}
      </h2>
    </div>

    <div class="aira-security-audit__content">
      <Message
        v-if="formState.message"
        :type="formState.messageType"
        :message="formState.message"
        :error-key="formState.messageKey"
        data-testid="security-message"
      />

      <!-- Security Events -->
      <div class="aira-security-audit__section">
        <h3 class="aira-security-audit__section-title">
          {{ localization?.audit_log_title || 'Security Events' }}
        </h3>
        
        <div v-if="auditEvents.length > 0" class="aira-security-audit__events">
          <div
            v-for="event in auditEvents"
            :key="event.id || Math.random()"
            class="aira-security-audit__event"
            data-testid="audit-event"
            :data-event-id="event.id"
          >
            <div class="aira-security-audit__event-header">
              <div class="aira-security-audit__event-type">
                {{ event.type || 'Unknown' }}
              </div>
              <div class="aira-security-audit__event-time">
                {{ formatEventTime(event.created_at || '') }}
              </div>
            </div>
            
            <div class="aira-security-audit__event-details">
              <div v-if="event.description" class="aira-security-audit__event-description">
                {{ event.description }}
              </div>
              
              <div class="aira-security-audit__event-meta">
                <div v-if="event.ip_address" class="aira-security-audit__event-meta-item">
                  <span class="aira-security-audit__event-meta-label">IP:</span>
                  <span class="aira-security-audit__event-meta-value">{{ event.ip_address }}</span>
                </div>
                
                <div v-if="event.user_agent" class="aira-security-audit__event-meta-item">
                  <span class="aira-security-audit__event-meta-label">Device:</span>
                  <span class="aira-security-audit__event-meta-value">{{ event.user_agent }}</span>
                </div>
                
                <div v-if="event.location" class="aira-security-audit__event-meta-item">
                  <span class="aira-security-audit__event-meta-label">Location:</span>
                  <span class="aira-security-audit__event-meta-value">{{ event.location }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div v-else class="aira-security-audit__empty">
          <p class="aira-security-audit__empty-text">
            {{ localization?.no_events_message || 'No security events found' }}
          </p>
        </div>
      </div>

      <!-- Trusted Devices -->
      <div class="aira-security-audit__section">
        <h3 class="aira-security-audit__section-title">
          {{ localization?.devices_title || 'Trusted Devices' }}
        </h3>
        
        <div v-if="devices.length > 0" class="aira-security-audit__devices">
          <div
            v-for="device in devices"
            :key="device.id || Math.random()"
            class="aira-security-audit__device"
            data-testid="trusted-device"
            :data-device-id="device.id"
          >
            <div class="aira-security-audit__device-header">
              <div class="aira-security-audit__device-name">
                {{ device.name || 'Unknown Device' }}
              </div>
              <div class="aira-security-audit__device-status">
                {{ device.status || 'Active' }}
              </div>
            </div>
            
            <div class="aira-security-audit__device-details">
              <div class="aira-security-audit__device-meta">
                <div v-if="device.device_type" class="aira-security-audit__device-meta-item">
                  <span class="aira-security-audit__device-meta-label">Type:</span>
                  <span class="aira-security-audit__device-meta-value">{{ device.device_type }}</span>
                </div>
                
                <div v-if="device.last_used" class="aira-security-audit__device-meta-item">
                  <span class="aira-security-audit__device-meta-label">Last used:</span>
                  <span class="aira-security-audit__device-meta-value">{{ formatEventTime(device.last_used || '') }}</span>
                </div>
                
                <div v-if="device.created_at" class="aira-security-audit__device-meta-item">
                  <span class="aira-security-audit__device-meta-label">Added:</span>
                  <span class="aira-security-audit__device-meta-value">{{ formatEventTime(device.created_at || '') }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div v-else class="aira-security-audit__empty">
          <p class="aira-security-audit__empty-text">
            {{ localization?.no_devices_message || 'No trusted devices found' }}
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import type { Types } from '@cybersailor/slauth-ts'
import { mergeLocalization } from '../../localization'
import type { Localization, AuthEvent } from '../../types'
import { useAuthContext } from '../../composables/useAuthContext'
import Message from '../ui/Message.vue'

interface SecurityAuditProps {
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


const props = defineProps<SecurityAuditProps>()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// Form state
const formState = ref<FormState>({
  loading: false
})

// Data
const auditEvents = ref<Record<string, any>[]>([])
const devices = ref<Record<string, any>[]>([])

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any).security_audit
)

// Load audit log
const loadAuditLog = async () => {
  formState.value.loading = true
  
  const result = await authClient.getAuditLog()
  auditEvents.value = result.events || []
  
  formState.value.loading = false
}

// Load devices
const loadDevices = async () => {
  formState.value.loading = true
  
  const result = await authClient.getDevices()
  devices.value = result.devices || []
  
  formState.value.loading = false
}

// Load all data
const loadData = async () => {
  formState.value.loading = true
  formState.value.message = undefined
  
  await Promise.all([
    loadAuditLog(),
    loadDevices()
  ])
  
  formState.value.loading = false
}

// Format event time
const formatEventTime = (timestamp: string): string => {
  const date = new Date(timestamp)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / (1000 * 60))
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
  
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString()
}

// Load data on mount
onMounted(() => {
  if (authClient.isAuthenticated()) {
    loadData()
  }
})

// Watch for auth state changes
watch(() => authClient.isAuthenticated(), (isAuthenticated) => {
  if (isAuthenticated) {
    loadData()
  } else {
    auditEvents.value = []
    devices.value = []
  }
})
</script>

<style scoped>
.aira-security-audit {
  width: 100%;
  max-width: 64rem;
  margin: 0 auto;
}

.aira-security-audit__header {
  margin-bottom: 1.5rem;
}

.aira-security-audit__title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-security-audit__content {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.aira-security-audit__section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-security-audit__section-title {
  font-size: 1.125rem;
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-security-audit__events {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.aira-security-audit__event {
  padding: 1rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
  background-color: var(--auth-ui-background);
}

.aira-security-audit__event-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.aira-security-audit__event-type {
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-security-audit__event-time {
  font-size: 0.875rem;
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.aira-security-audit__event-details {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-security-audit__event-description {
  font-size: 0.875rem;
  color: var(--auth-ui-text-secondary);
  margin: 0;
}

.aira-security-audit__event-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  font-size: 0.75rem;
}

.aira-security-audit__event-meta-item {
  display: flex;
  gap: 0.25rem;
}

.aira-security-audit__event-meta-label {
  color: var(--auth-ui-text-tertiary);
  font-weight: 500;
}

.aira-security-audit__event-meta-value {
  color: var(--auth-ui-text-secondary);
}

.aira-security-audit__devices {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.aira-security-audit__device {
  padding: 1rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
  background-color: var(--auth-ui-background);
}

.aira-security-audit__device-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.aira-security-audit__device-name {
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-security-audit__device-status {
  font-size: 0.875rem;
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.aira-security-audit__device-details {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.aira-security-audit__device-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  font-size: 0.75rem;
}

.aira-security-audit__device-meta-item {
  display: flex;
  gap: 0.25rem;
}

.aira-security-audit__device-meta-label {
  color: var(--auth-ui-text-tertiary);
  font-weight: 500;
}

.aira-security-audit__device-meta-value {
  color: var(--auth-ui-text-secondary);
}

.aira-security-audit__empty {
  text-align: center;
  padding: 2rem 0;
}

.aira-security-audit__empty-text {
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}
</style>
