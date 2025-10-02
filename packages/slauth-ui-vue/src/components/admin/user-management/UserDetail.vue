<template>
  <div class="user-detail">
    <!-- View Mode -->
    <template v-if="!isCreating && !isEditing">
      <!-- User Profile Card -->
      <div class="user-detail__card">
        <div class="user-detail__card-header">
          <div class="user-detail__header-left">
            <UserAvatar />
            <div class="user-detail__header-info">
              <h3 class="user-detail__name">
                {{ user?.email }}
                <span v-if="user?.is_anonymous" class="user-detail__badge">Anonymous</span>
              </h3>
              <p class="user-detail__id">{{ user?.id }}</p>
            </div>
          </div>
          <span v-if="isBanned" class="user-detail__status-badge user-detail__status-badge--banned">
            ⛔ Banned{{ user?.banned_until ? ` (Until ${formatDate(user.banned_until)})` : '' }}
          </span>
          <span v-else class="user-detail__status-badge user-detail__status-badge--active">
            ✓ Active
          </span>
        </div>
        <div class="user-detail__card-body">
          <div class="user-detail__contact-list">
            <div class="user-detail__contact-item">
              <ContactIcon type="email" class="user-detail__contact-icon" />
              <span class="user-detail__contact-value">{{ user?.email || 'N/A' }}</span>
              <span v-if="user?.email_confirmed" class="user-detail__verified">✓ Verified</span>
              <Button
                v-else
                variant="ghost"
                size="sm"
                @click="handleVerifyEmail"
              >
                Mark as Verified
              </Button>
            </div>
            <div class="user-detail__contact-item">
              <ContactIcon type="phone" class="user-detail__contact-icon" />
              <span class="user-detail__contact-value">{{ user?.phone || 'N/A' }}</span>
              <span v-if="user?.phone_confirmed" class="user-detail__verified">✓ Verified</span>
              <Button
                v-else-if="user?.phone"
                variant="ghost"
                size="sm"
                @click="handleVerifyPhone"
              >
                Mark as Verified
              </Button>
            </div>
          </div>
        </div>
      </div>

      <!-- Sessions Card -->
      <div v-if="showSessions" class="user-detail__card">
        <div class="user-detail__card-header">
          <h4 class="user-detail__card-title">Active Sessions ({{ sessions.length }})</h4>
          <Button
            v-if="sessions.length > 0"
            variant="outline"
            size="sm"
            @click="handleRevokeAllSessions"
          >
            Revoke All
          </Button>
        </div>
        <div class="user-detail__card-body">
          <div v-if="loadingSessions" class="user-detail__loading">Loading sessions...</div>
          <div v-else-if="sessions.length === 0" class="user-detail__empty">No active sessions</div>
          <div v-else class="user-detail__sessions">
            <div v-for="session in sessions" :key="session.id" class="user-detail__session-item">
              <div class="user-detail__session-info">
                <div class="user-detail__session-device">{{ parseUserAgent(session.user_agent) }}</div>
                <div class="user-detail__session-meta">
                  <span>{{ session.ip }}</span>
                  <span>•</span>
                  <span>{{ formatDate(session.refreshed_at) }}</span>
                </div>
              </div>
              <Button variant="ghost" size="sm" @click="handleRevokeSession(session.id)">
                Revoke
              </Button>
            </div>
          </div>
        </div>
      </div>

      <!-- Connected Accounts Card -->
      <div v-if="showConnected" class="user-detail__card">
        <div class="user-detail__card-header">
          <h4 class="user-detail__card-title">Connected Accounts</h4>
        </div>
        <div class="user-detail__card-body">
          <div v-if="loadingIdentities" class="user-detail__loading">Loading identities...</div>
          <div v-else-if="identities.length === 0" class="user-detail__empty">No connected accounts</div>
          <div v-else class="user-detail__identities">
            <div v-for="identity in identities" :key="identity.id" class="user-detail__identity-item">
              <div class="user-detail__identity-info">
                <div class="user-detail__identity-provider">{{ identity.provider }}</div>
                <div class="user-detail__identity-email">{{ identity.email }}</div>
              </div>
              <Button variant="ghost" size="sm" @click="handleDeleteIdentity(identity.id)">
                Unbind
              </Button>
            </div>
          </div>
        </div>
      </div>

      <!-- App Metadata Card -->
      <div v-if="showAppMetadata" class="user-detail__card">
        <div class="user-detail__card-header">
          <h4 class="user-detail__card-title">App Metadata</h4>
        </div>
        <div class="user-detail__card-body">
          <JsonEditor
            :model-value="formatJSON(user?.app_meta_data)"
            readonly
          />
        </div>
      </div>

      <!-- User Metadata Card -->
      <div v-if="showUserMetadata" class="user-detail__card">
        <div class="user-detail__card-header">
          <h4 class="user-detail__card-title">User Metadata</h4>
        </div>
        <div class="user-detail__card-body">
          <JsonEditor
            :model-value="formatJSON(user?.user_meta_data)"
            readonly
          />
        </div>
      </div>

      <!-- User Detail Slot (View Mode) -->
      <div v-if="$slots['user-detail']" class="user-detail__slot">
        <slot name="user-detail" :user="user" :view="'view'" />
      </div>

      <!-- Operations -->
      <div class="user-detail__operations">
        <a 
          class="user-detail__operation-item" 
          @click="isEditing = true"
          data-testid="admin-users-edit-link"
        >
          <span class="user-detail__operation-icon">
            <ActionIcon type="edit" />
          </span>
          <span class="user-detail__operation-text">Edit</span>
        </a>
        <a 
          class="user-detail__operation-item" 
          @click="showResetPasswordDialog = true"
          data-testid="admin-users-reset-password-link"
        >
          <span class="user-detail__operation-icon">
            <ActionIcon type="password" />
          </span>
          <span class="user-detail__operation-text">Change Password</span>
        </a>
        <a 
          class="user-detail__operation-item" 
          @click="isBanned ? handleUnban() : showBanDialog = true"
          data-testid="admin-users-ban-link"
        >
          <span class="user-detail__operation-icon">
            <ActionIcon :type="isBanned ? 'unban' : 'ban'" />
          </span>
          <span class="user-detail__operation-text">{{ isBanned ? 'Unban User' : 'Ban User' }}</span>
        </a>
        <a 
          class="user-detail__operation-item user-detail__operation-item--danger" 
          @click="$emit('delete')"
          data-testid="admin-users-delete-link"
        >
          <span class="user-detail__operation-icon">
            <ActionIcon type="delete" />
          </span>
          <span class="user-detail__operation-text">Delete User</span>
        </a>
      </div>

      <!-- Ban User Dialog -->
      <Dialog v-model="showBanDialog" title="Ban User" width="500px">
        <Input
          v-model="banUntilDate"
          type="text"
          label="Ban Until (leave empty for permanent ban)"
          placeholder="2024-12-31T23:59:59Z"
        />
        <template #footer>
          <Button variant="secondary" @click="showBanDialog = false">Cancel</Button>
          <Button variant="primary" @click="handleBanUser">Confirm Ban</Button>
        </template>
      </Dialog>

      <!-- Reset Password Dialog -->
      <Dialog v-model="showResetPasswordDialog" title="Reset Password" width="500px">
        <Input
          v-model="newPassword"
          type="password"
          label="New Password"
          placeholder="Enter new password"
        />
        <template #footer>
          <Button variant="secondary" @click="showResetPasswordDialog = false">Cancel</Button>
          <Button variant="primary" :loading="resettingPassword" @click="handleResetPassword">
            Reset Password
          </Button>
        </template>
      </Dialog>
    </template>

    <!-- Edit Mode -->
    <template v-else>
      <div class="user-detail__section">
        <h4 class="user-detail__section-title">Basic Information</h4>
        
        <Input
          v-model="formData.email"
          type="email"
          label="Email"
          placeholder="user@example.com"
          data-testid="admin-users-email-input"
        />
        
        <Input
          v-if="isCreating"
          v-model="formData.password"
          type="password"
          label="Password"
          placeholder="••••••••"
          data-testid="admin-users-password-input"
          required
        />
        
        <Input
          v-model="formData.phone"
          type="tel"
          label="Phone (optional)"
          placeholder="+1234567890"
          data-testid="admin-users-phone-input"
        />
      </div>

      <div v-if="!isCreating && showAppMetadata" class="user-detail__section">
        <JsonEditor
          v-model="formData.app_metadata_json"
          label="App Metadata"
          placeholder='{"level": "admin", "role": "manager"}'
        />
      </div>

      <div v-if="!isCreating && showUserMetadata" class="user-detail__section">
        <JsonEditor
          v-model="formData.user_metadata_json"
          label="User Metadata"
          placeholder='{"preference": "dark", "language": "en"}'
        />
      </div>

      <!-- User Detail Slot (Edit/Insert Mode) -->
      <div v-if="$slots['user-detail']" class="user-detail__slot">
        <slot name="user-detail" :user="user" :view="isCreating ? 'insert' : 'edit'" />
      </div>

      <div class="user-detail__actions">
        <Button
          variant="secondary"
          data-testid="admin-users-cancel-button"
          @click="handleCancel"
        >
          Cancel
        </Button>
        <Button
          variant="primary"
          :loading="submitting"
          data-testid="admin-users-submit-button"
          @click="$emit('submit', formData)"
        >
          {{ isCreating ? 'Create' : 'Save Changes' }}
        </Button>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed, onMounted } from 'vue'
import Button from '../../ui/Button.vue'
import Input from '../../ui/Input.vue'
import Dialog from '../../ui/Dialog.vue'
import JsonEditor from '../../ui/JsonEditor.vue'
import UserAvatar from '../../ui/icons/UserAvatar.vue'
import ContactIcon from '../../ui/icons/ContactIcons.vue'
import ActionIcon from '../../ui/icons/ActionIcons.vue'
import { useAdminContext } from '../../../composables/useAdminContext'
import type { AdminUserResponse } from '@cybersailor/slauth-ts'

interface Props {
  user?: AdminUserResponse | null
  isCreating: boolean
  submitting: boolean
}

const props = defineProps<Props>()

const emit = defineEmits<{
  submit: [formData: any]
  cancel: []
  delete: []
  refresh: []
}>()

const adminContext = useAdminContext()
const adminClient = adminContext.value.adminClient

// User detail sections configuration
const userDetailSections = computed(() => {
  const sections = adminContext.value.userDetailSections
  // If sections is undefined (not provided), show all by default
  // If sections is an empty array (explicitly set to []), show none
  if (sections === undefined) {
    return ['sessions', 'connected', 'app_metadata', 'user_metadata']
  }
  return sections
})

// Section visibility computed properties
const showSessions = computed(() => userDetailSections.value.includes('sessions'))
const showConnected = computed(() => userDetailSections.value.includes('connected'))
const showAppMetadata = computed(() => userDetailSections.value.includes('app_metadata'))
const showUserMetadata = computed(() => userDetailSections.value.includes('user_metadata'))

const isEditing = ref(false)
const sessions = ref<any[]>([])
const identities = ref<any[]>([])
const loadingSessions = ref(false)
const loadingIdentities = ref(false)
const showBanDialog = ref(false)
const showResetPasswordDialog = ref(false)
const banUntilDate = ref('')
const newPassword = ref('')
const resettingPassword = ref(false)

const formData = ref({
  email: '',
  password: '',
  phone: '',
  app_metadata_json: '',
  user_metadata_json: ''
})

const isBanned = computed(() => {
  if (!props.user?.banned_until) return false
  const bannedUntil = new Date(props.user.banned_until)
  return bannedUntil > new Date()
})

watch(() => props.user, async (user) => {
  isEditing.value = false
  if (user) {
    formData.value = {
      email: user.email || '',
      password: '',
      phone: user.phone || '',
      app_metadata_json: JSON.stringify(user.app_meta_data || {}, null, 2),
      user_metadata_json: JSON.stringify(user.user_meta_data || {}, null, 2)
    }
    await loadUserData()
  } else {
    formData.value = {
      email: '',
      password: '',
      phone: '',
      app_metadata_json: '',
      user_metadata_json: ''
    }
    sessions.value = []
    identities.value = []
  }
}, { immediate: true })

const loadUserData = async () => {
  if (!props.user?.id) return

  loadingSessions.value = true
  loadingIdentities.value = true

  const [sessionsResult, identitiesResult] = await Promise.allSettled([
    adminClient.listUserSessions(props.user.id),
    adminClient.listUserIdentities(props.user.id)
  ])

  if (sessionsResult.status === 'fulfilled') {
    sessions.value = sessionsResult.value.sessions || []
  }

  if (identitiesResult.status === 'fulfilled') {
    identities.value = identitiesResult.value.identities || []
  }

  loadingSessions.value = false
  loadingIdentities.value = false
}

const handleCancel = () => {
  if (props.isCreating) {
    emit('cancel')
  } else {
    isEditing.value = false
  }
}

const handleVerifyEmail = async () => {
  if (!props.user?.id) return
  await adminClient.setUserEmailConfirmed(props.user.id, true)
  emit('refresh')
}

const handleVerifyPhone = async () => {
  if (!props.user?.id) return
  await adminClient.setUserPhoneConfirmed(props.user.id, true)
  emit('refresh')
}

const handleBanUser = async () => {
  if (!props.user?.id) return
  
  const bannedUntil = banUntilDate.value 
    ? new Date(banUntilDate.value).toISOString() 
    : '2099-12-31T23:59:59Z'
  
  await adminClient.updateUser(props.user.id, { banned_until: bannedUntil })
  showBanDialog.value = false
  banUntilDate.value = ''
  emit('refresh')
}

const handleUnban = async () => {
  if (!props.user?.id) return
  await adminClient.updateUser(props.user.id, { banned_until: new Date().toISOString() })
  emit('refresh')
}

const handleRevokeSession = async (sessionId: string) => {
  if (confirm('Revoke this session?')) {
    await adminClient.revokeSession(sessionId)
    await loadUserData()
  }
}

const handleRevokeAllSessions = async () => {
  if (!props.user?.id) return
  if (confirm('Revoke all sessions for this user?')) {
    await adminClient.revokeAllUserSessions(props.user.id)
    await loadUserData()
  }
}

const handleDeleteIdentity = async (identityId: string) => {
  if (!props.user?.id) return
  if (confirm('Unbind this account?')) {
    await adminClient.deleteUserIdentity(props.user.id, identityId)
    await loadUserData()
  }
}

const handleResetPassword = async () => {
  if (!props.user?.id || !newPassword.value) return
  
  resettingPassword.value = true
  await adminClient.resetUserPassword(props.user.id, { new_password: newPassword.value })
  resettingPassword.value = false
  showResetPasswordDialog.value = false
  newPassword.value = ''
  alert('Password reset successfully')
}

const formatDate = (dateString: string | undefined) => {
  if (!dateString) return 'N/A'
  return new Date(dateString).toLocaleString()
}

const formatJSON = (obj: any) => {
  if (!obj || Object.keys(obj).length === 0) return '{}'
  return JSON.stringify(obj, null, 2)
}

const parseUserAgent = (ua: string | undefined) => {
  if (!ua) return 'Unknown Device'
  if (ua.includes('Chrome')) return 'Chrome Browser'
  if (ua.includes('Safari')) return 'Safari Browser'
  if (ua.includes('Firefox')) return 'Firefox Browser'
  if (ua.includes('Mobile')) return 'Mobile Device'
  return ua.substring(0, 50)
}
</script>

<style scoped>
.user-detail {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.user-detail__header-left {
  display: flex;
  align-items: center;
  gap: 16px;
  flex: 1;
}

.user-detail__header-info {
  flex: 1;
}

.user-detail__name {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--admin-text, #374151);
  display: flex;
  align-items: center;
  gap: 8px;
}

.user-detail__badge {
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  background: #fbbf24;
  color: #78350f;
  border-radius: 12px;
}

.user-detail__id {
  margin: 4px 0 0;
  font-size: 12px;
  font-family: monospace;
  color: #6b7280;
}

/* Card Styles */
.user-detail__card {
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 8px;
  background: var(--admin-card-bg, white);
  overflow: hidden;
}

.user-detail__card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--admin-border, #e5e7eb);
  background: var(--admin-bg, #f9fafb);
}

.user-detail__card-title {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--admin-text, #374151);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.user-detail__card-body {
  padding: 16px;
}

/* Section Styles */
.user-detail__section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.user-detail__section-title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--admin-text, #374151);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Info Grid */
.user-detail__info-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
}

@media (min-width: 768px) {
  .user-detail__info-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1024px) {
  .user-detail__info-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}

/* Info List (vertical stack) */
.user-detail__info-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.user-detail__info-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

/* Contact List */
.user-detail__contact-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.user-detail__contact-item {
  display: flex;
  align-items: center;
  gap: 12px;
}

.user-detail__contact-icon {
  width: 48px;
  flex-shrink: 0;
  color: #6b7280;
  display: flex;
  justify-content: flex-end;
  align-items: center;
}

.user-detail__contact-value {
  font-size: 14px;
  color: var(--admin-text, #374151);
  flex: 1;
}

.user-detail__info-label {
  font-size: 11px;
  font-weight: 600;
  color: #9ca3af;
  text-transform: uppercase;
}

.user-detail__info-value {
  font-size: 14px;
  color: var(--admin-text, #374151);
}

.user-detail__info-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.user-detail__verified {
  font-size: 12px;
  color: #10b981;
  font-weight: 500;
}

.user-detail__status-badge {
  font-size: 12px;
  font-weight: 500;
  padding: 4px 10px;
  border-radius: 12px;
  display: inline-block;
  white-space: nowrap;
}

.user-detail__status-badge--active {
  color: #10b981;
  background: rgba(16, 185, 129, 0.1);
}

.user-detail__status-badge--banned {
  color: #ef4444;
  background: rgba(239, 68, 68, 0.1);
}

/* Sessions */
.user-detail__sessions {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.user-detail__session-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 6px;
}

.user-detail__session-info {
  flex: 1;
}

.user-detail__session-device {
  font-size: 14px;
  font-weight: 500;
  color: var(--admin-text, #374151);
  margin-bottom: 4px;
}

.user-detail__session-meta {
  font-size: 12px;
  color: #6b7280;
  display: flex;
  gap: 6px;
}

/* Identities */
.user-detail__identities {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.user-detail__identity-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 6px;
}

.user-detail__identity-info {
  flex: 1;
}

.user-detail__identity-provider {
  font-size: 14px;
  font-weight: 500;
  color: var(--admin-text, #374151);
  margin-bottom: 4px;
  text-transform: capitalize;
}

.user-detail__identity-email {
  font-size: 12px;
  color: #6b7280;
}

/* Loading & Empty States */
.user-detail__loading,
.user-detail__empty {
  text-align: center;
  padding: 24px;
  color: #9ca3af;
  font-size: 14px;
}

/* JSON Editor in cards */
.user-detail__card-body :deep(.aira-json-editor) {
  margin-bottom: 0;
}

.user-detail__card-body :deep(.aira-json-editor__field) {
  min-height: 80px;
}

/* User Detail Slot */
.user-detail__slot {
  padding: 16px;
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 8px;
  background: var(--admin-card-bg, white);
  margin-bottom: 16px;
}

/* Operations */
.user-detail__operations {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 16px 24px 0;
}

.user-detail__operation-item {
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  transition: color 0.2s;
  color: var(--admin-text, #374151);
}

.user-detail__operation-item:hover {
  color: #3b82f6;
}

.user-detail__operation-icon {
  width: 48px;
  flex-shrink: 0;
  display: flex;
  justify-content: flex-end;
  align-items: center;
  color: #6b7280;
}

.user-detail__operation-item:hover .user-detail__operation-icon {
  color: inherit;
}

.user-detail__operation-text {
  font-size: 14px;
  flex: 1;
}

.user-detail__operation-item--danger {
  color: #ef4444;
}

.user-detail__operation-item--danger:hover {
  color: #dc2626;
}

.user-detail__operation-item--danger .user-detail__operation-icon {
  color: #ef4444;
}

.user-detail__operation-item--danger:hover .user-detail__operation-icon {
  color: #dc2626;
}
</style>
