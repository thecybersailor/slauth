<template>
  <div class="aira-session-table-wrapper">
    <table class="aira-session-table" data-testid="session-table">
      <thead>
        <tr>
          <th class="aira-session-table__th">{{ localization?.device_label || 'Device' }}</th>
          <th class="aira-session-table__th">{{ localization?.location_label || 'Location' }}</th>
          <th class="aira-session-table__th">{{ localization?.last_active_label || 'Last Active' }}</th>
          <th class="aira-session-table__th aira-session-table__th--actions"></th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="apiSession in apiSessions"
          :key="apiSession.id"
          class="aira-session-table__row"
          :data-session-id="apiSession.id"
          data-testid="session-row"
        >
          <td class="aira-session-table__td aira-session-table__td--device">
            <div class="aira-session-table__device">
              <DeviceIcons :type="getSession(apiSession).device_type" class="aira-session-table__device-icon" />
              <span class="aira-session-table__device-name">
                {{ getSession(apiSession).device_name }}
              </span>
            </div>
          </td>
          <td class="aira-session-table__td">{{ getSession(apiSession).location }}</td>
          <td class="aira-session-table__td">{{ formatLastActive(getSession(apiSession).last_active) }}</td>
          <td class="aira-session-table__td aira-session-table__td--actions">
            <span v-if="getSession(apiSession).is_current" class="aira-session-table__current-badge">
              {{ localization?.current_session_label || 'Current' }}
            </span>
            <Button
              v-else
              :variant="'outline'"
              :size="'sm'"
              :disabled="loading"
              @click="$emit('revoke', apiSession.id)"
              data-testid="revoke-session-button"
            >
              {{ localization?.revoke_button_label || 'Revoke' }}
            </Button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import Button from './Button.vue'
import DeviceIcons from './icons/DeviceIcons.vue'
// @ts-ignore
import UAParser from 'ua-parser-js'

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

interface Session {
  id: string
  device_name: string
  device_type: 'desktop' | 'mobile' | 'tablet' | 'unknown'
  browser: string
  os: string
  location: string
  ip_address: string
  last_active: string
  created_at: string
  is_current: boolean
}

interface SessionItemLocalization {
  current_session_label?: string
  revoke_button_label?: string
  location_label?: string
  last_active_label?: string
  device_label?: string
}

interface SessionItemProps {
  apiSessions: ApiSession[]
  currentSessionId?: string
  loading?: boolean
  localization?: SessionItemLocalization
}

const props = defineProps<SessionItemProps>()

defineEmits<{
  revoke: [sessionId: string]
}>()

// Parse user agent to extract device info using ua-parser-js
const parseUserAgent = (userAgent: string) => {
  const parser = new UAParser(userAgent)
  const result = parser.getResult()
  
  // Extract browser info
  const browser = result.browser.name || 'Unknown'
  const browserVersion = result.browser.version ? ` ${result.browser.version}` : ''
  
  // Extract OS info
  const os = result.os.name || 'Unknown'
  const osVersion = result.os.version ? ` ${result.os.version}` : ''
  
  // Extract device info - map to expected values for DeviceIcons
  let deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown' = 'unknown'
  if (result.device.type === 'mobile') deviceType = 'mobile'
  else if (result.device.type === 'tablet') deviceType = 'tablet'
  else if (result.device.type === undefined || result.device.type === 'desktop') deviceType = 'desktop'
  
  const deviceModel = result.device.model || ''
  
  return { 
    browser: `${browser}${browserVersion}`, 
    os: `${os}${osVersion}`, 
    deviceType,
    deviceModel
  }
}

// Parse IP address to get location (simplified)
const parseLocation = (ip: string) => {
  // For localhost/IPv6 localhost
  if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') {
    return 'Local'
  }
  
  // For now, just return the IP. In a real app, you'd use a geolocation service
  return ip
}

// Convert API session to display session
const getSession = (apiSession: ApiSession): Session => {
  const { browser, os, deviceType, deviceModel } = apiSession.user_agent 
    ? parseUserAgent(apiSession.user_agent)
    : { browser: 'Unknown', os: 'Unknown', deviceType: 'unknown' as const, deviceModel: '' }
  
  // Create a more descriptive device name
  let deviceName = `${browser} on ${os}`
  if (deviceModel && deviceType !== 'desktop') {
    deviceName = `${deviceModel} (${browser})`
  }
  
  return {
    id: apiSession.id,
    device_name: deviceName,
    device_type: deviceType,
    browser,
    os,
    location: apiSession.ip ? parseLocation(apiSession.ip) : 'Unknown',
    ip_address: apiSession.ip,
    last_active: apiSession.refreshed_at || apiSession.updated_at || apiSession.created_at || '',
    created_at: apiSession.created_at || '',
    is_current: props.currentSessionId ? apiSession.id === props.currentSessionId : false
  }
}

const formatLastActive = (lastActive: string): string => {
  const date = new Date(lastActive)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / (1000 * 60))
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
  
  return date.toLocaleDateString()
}
</script>

<style scoped>
.aira-session-table-wrapper {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
  background-color: var(--auth-ui-background);
}

.aira-session-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.aira-session-table__th {
  padding: 0.75rem 1rem;
  text-align: left;
  font-weight: 600;
  color: var(--auth-ui-text-tertiary);
  background-color: var(--auth-ui-background);
  border-bottom: 1px solid var(--auth-ui-border);
  white-space: nowrap;
}

.aira-session-table__th--actions {
  width: 150px;
  text-align: right;
}

.aira-session-table__row {
  transition: background-color 0.15s ease;
}

.aira-session-table__row:hover {
  background-color: var(--auth-ui-hover-bg, rgba(0, 0, 0, 0.02));
}

.aira-session-table__td {
  padding: 0.75rem 1rem;
  color: var(--auth-ui-text);
  border-bottom: 1px solid var(--auth-ui-border);
  vertical-align: middle;
}

.aira-session-table__row:last-child .aira-session-table__td {
  border-bottom: none;
}

.aira-session-table__td--device {
  font-weight: 500;
}

.aira-session-table__td--actions {
  text-align: right;
}

.aira-session-table__device {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.aira-session-table__device-icon {
  flex-shrink: 0;
}

.aira-session-table__device-name {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.aira-session-table__current-badge {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.5rem;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: 500;
  background-color: var(--auth-ui-info-bg);
  color: var(--auth-ui-info-text);
  white-space: nowrap;
}
</style>