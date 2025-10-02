<template>
  <Table
    :columns="columns"
    :data="sessions"
    row-key="id"
    test-id="session-table"
  >
    <template #cell-device="{ row }">
      <div class="aira-session-device">
        <DeviceIcons :type="row.device_type" class="aira-session-device-icon" />
        <span class="aira-session-device-name">{{ row.device_name }}</span>
      </div>
    </template>

    <template #cell-location="{ row }">
      {{ row.location }}
    </template>

    <template #cell-last_active="{ row }">
      {{ formatLastActive(row.last_active) }}
    </template>

    <template #cell-actions="{ row }">
      <span v-if="row.is_current" class="aira-session-current-badge">
        {{ localization?.current_session_label || 'Current' }}
      </span>
      <Button
        v-else
        :variant="'outline'"
        :size="'sm'"
        :disabled="loading"
        @click="$emit('revoke', row.id)"
        data-testid="revoke-session-button"
      >
        {{ localization?.revoke_button_label || 'Revoke' }}
      </Button>
    </template>
  </Table>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import Table from './Table.vue'
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
  shortDeviceLabel?: boolean
}

const props = withDefaults(defineProps<SessionItemProps>(), {
  shortDeviceLabel: false
})

defineEmits<{
  revoke: [sessionId: string]
}>()

const columns = computed(() => [
  {
    key: 'location',
    label: props.localization?.location_label || 'Location'
  },
  {
    key: 'last_active',
    label: props.localization?.last_active_label || 'Last Active'
  },
  {
    key: 'device',
    label: props.localization?.device_label || 'Device',
    tdClass: 'aira-table__td--device'
  },
  {
    key: 'actions',
    label: '',
    thClass: 'aira-table__th--actions',
    tdClass: 'aira-table__td--actions'
  }
])

const sessions = computed(() => props.apiSessions.map(getSession))

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
  const parsed = apiSession.user_agent 
    ? parseUserAgent(apiSession.user_agent)
    : { browser: 'Unknown', os: 'Unknown', deviceType: 'unknown' as const, deviceModel: '' }
  
  // Extract browser and OS names without versions
  const browserName = parsed.browser.split(' ')[0]
  const osName = parsed.os.split(' ')[0]
  
  // Create device name based on shortDeviceLabel prop
  let deviceName: string
  if (props.shortDeviceLabel) {
    // Short format: "Chrome, macOS"
    if (parsed.deviceModel && parsed.deviceType !== 'desktop') {
      deviceName = `${parsed.deviceModel}, ${browserName}`
    } else {
      deviceName = `${browserName}, ${osName}`
    }
  } else {
    // Long format: "Chrome 120 on macOS 14"
    if (parsed.deviceModel && parsed.deviceType !== 'desktop') {
      deviceName = `${parsed.deviceModel} (${parsed.browser})`
    } else {
      deviceName = `${parsed.browser}, ${parsed.os}`
    }
  }
  
  return {
    id: apiSession.id,
    device_name: deviceName,
    device_type: parsed.deviceType,
    browser: parsed.browser,
    os: parsed.os,
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
.aira-table__th--actions {
  width: 150px;
  text-align: right;
}

.aira-table__td--device {
  font-weight: 500;
}

.aira-table__td--actions {
  text-align: right;
}

.aira-session-device {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.aira-session-device-icon {
  flex-shrink: 0;
}

.aira-session-device-name {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.aira-session-current-badge {
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