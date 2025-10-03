<template>
  <div :class="['admin-users', { 'admin-users--dark': darkMode }]">
    <div class="admin-users__header">
      <h2 class="admin-users__title">{{ t.title || 'User Management' }}</h2>
      <Button
        variant="primary"
        data-testid="admin-users-create-button"
        @click="openCreateDrawer"
      >
        {{ t.create_user || 'Create User' }}
      </Button>
    </div>

    <div v-if="loading" class="admin-users__loading">Loading...</div>
    
    <div v-else-if="users.length === 0" class="admin-users__empty">
      {{ t.no_users || 'No users found' }}
    </div>

    <div v-else class="admin-users__container">
      <!-- Custom filter slot -->
      <div v-if="$slots['user-filter']" class="admin-users__filter">
        <slot 
          name="user-filter" 
          :app_metadata="filterData.app_metadata"
          :user_metadata="filterData.user_metadata"
        />
      </div>

      <div class="admin-users__list">
        <div
          v-for="user in filteredUsers"
          :key="user.id"
          class="admin-users__item"
          @click="viewUser(user)"
        >
          <!-- Custom user row slot -->
          <template v-if="$slots['user-row']">
            <slot name="user-row" :user="user" />
          </template>
          
          <!-- Default user row content -->
          <template v-else>
            <UserAvatar />
            <div class="admin-users__content">
              <div class="admin-users__field">
                <span class="admin-users__label">Email</span>
                <span class="admin-users__email">{{ user.email }}</span>
              </div>
              <div class="admin-users__field">
                <span class="admin-users__label">ID</span>
                <span class="admin-users__id">{{ user.id }}</span>
              </div>
              <div class="admin-users__field">
                <span class="admin-users__label">Last Active</span>
                <span class="admin-users__last-active">{{ formatDate(user.last_sign_in_at) || 'Never' }}</span>
              </div>
              <div class="admin-users__field">
                <span class="admin-users__label">Metadata</span>
                <span class="admin-users__metadata">{{ formatMetadata(user.app_metadata) }}</span>
              </div>
            </div>
          </template>
        </div>
      </div>
    </div>

    <!-- Create/Edit User Drawer -->
    <Drawer
      v-model="showDrawer"
      direction="rtl"
      size="600px"
      :title="isCreating ? (t.create_user || 'Create User') : (editingUser?.email || 'User Details')"
    >
      <UserDetail
        ref="userDetailRef"
        :key="editingUser?.id || 'new'"
        :user="editingUser"
        :is-creating="isCreating"
        :submitting="submitting"
        @submit="isCreating ? createUserSubmit($event) : updateUserSubmit($event)"
        @cancel="closeDrawer"
        @delete="deleteUserConfirm"
        @refresh="refreshCurrentUser"
      >
        <template v-if="$slots['user-detail']" #user-detail="slotProps">
          <slot name="user-detail" v-bind="slotProps" />
        </template>
      </UserDetail>
    </Drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'
import Button from '../../ui/Button.vue'
import Drawer from '../../ui/Drawer.vue'
import UserDetail from './UserDetail.vue'
import UserAvatar from '../../ui/icons/UserAvatar.vue'
import type { AdminUserResponse } from '@cybersailor/slauth-ts'

export interface UserManagementSlots {
  'user-filter'?: (props: {
    app_metadata: Record<string, any>
    user_metadata: Record<string, any>
  }) => any
  'user-row'?: (props: { user: AdminUserResponse }) => any
  'user-detail'?: (props: { user: AdminUserResponse | null | undefined; viewMode: 'view' | 'edit' | 'insert' }) => any
}

defineSlots<UserManagementSlots>()

const adminContext = useAdminContext()
const adminClient = adminContext.value.adminClient
const darkMode = computed(() => adminContext.value.darkMode ?? false)
const t = computed(() => adminContext.value.localization?.admin?.user_management || {})

const users = ref<AdminUserResponse[]>([])
const loading = ref(false)
const showDrawer = ref(false)
const editingUser = ref<AdminUserResponse | null>(null)
const submitting = ref(false)
const isCreating = ref(false)
const userDetailRef = ref<InstanceType<typeof UserDetail> | null>(null)

const filterData = ref<{
  app_metadata: Record<string, any>
  user_metadata: Record<string, any>
}>({
  app_metadata: {},
  user_metadata: {}
})

// Use backend query to filter users
const filteredUsers = computed(() => users.value)

const loadUsers = async () => {
  loading.value = true
  
  // Build backend query filters
  const filters: Record<string, any> = {}
  
  // Add app_metadata filters to query
  // Note: Backend currently doesn't support nested JSON field queries, so we filter on frontend
  // If backend filtering is needed, implement app_metadata.field query syntax
  
  const result = await adminClient.queryUsers({
    filters,
    sort: ['created_at desc'],
    pagination: {
      page: 1,
      pageSize: 100
    }
  })
  
  // If there are app_metadata filters, filter on frontend
  let filteredResult = result.users || []
  const appFilters = filterData.value.app_metadata
  if (appFilters && Object.keys(appFilters).length > 0) {
    filteredResult = filteredResult.filter((user: any) => {
      if (!user.app_metadata) return false
      return Object.entries(appFilters).every(([key, value]) => {
        if (!value) return true
        return user.app_metadata?.[key] === value
      })
    })
  }
  
  users.value = filteredResult
  loading.value = false
}

const openCreateDrawer = () => {
  isCreating.value = true
  editingUser.value = null
  showDrawer.value = true
}

const viewUser = async (user: any) => {
  console.log('[Index] Opening user detail for:', user.id, user.email)
  isCreating.value = false
  editingUser.value = user
  showDrawer.value = true
  
  // Wait for next tick to ensure component is mounted with the key change
  await new Promise(resolve => setTimeout(resolve, 0))
  
  // Explicitly load user data
  if (userDetailRef.value) {
    console.log('[Index] Calling userDetail.load()')
    await userDetailRef.value.load()
  } else {
    console.warn('[Index] userDetailRef not available')
  }
}

const deleteUserConfirm = async () => {
  if (!editingUser.value?.id) return
  if (confirm(`Delete user ${editingUser.value.email}?`)) {
    await adminClient.deleteUser(editingUser.value.id!)
    closeDrawer()
    await loadUsers()
  }
}

const closeDrawer = () => {
  showDrawer.value = false
  isCreating.value = false
  editingUser.value = null
}

const refreshCurrentUser = async () => {
  if (!editingUser.value?.id) return
  const updatedUser = await adminClient.getUser(editingUser.value.id)
  editingUser.value = updatedUser
  await loadUsers()
}

const createUserSubmit = async (formData: any) => {
  submitting.value = true
  
  await adminClient.createUser({
    email: formData.email,
    password: formData.password,
    phone: formData.phone || undefined,
    email_confirmed: false,
    phone_confirmed: false
  })
  
  submitting.value = false
  closeDrawer()
  await loadUsers()
}

const updateUserSubmit = async (formData: any) => {
  if (!editingUser.value?.id) return
  
  submitting.value = true
  
  let app_metadata
  let user_data
  
  if (formData.app_metadata_json) {
    app_metadata = JSON.parse(formData.app_metadata_json)
  }
  
  if (formData.user_metadata_json) {
    user_data = JSON.parse(formData.user_metadata_json)
  }
  
  await adminClient.updateUser(editingUser.value.id!, {
    email: formData.email,
    phone: formData.phone || undefined,
    app_metadata,
    user_data
  })
  
  submitting.value = false
  closeDrawer()
  await loadUsers()
}

const formatMetadata = (metadata: any) => {
  if (!metadata) return ''
  return Object.entries(metadata)
    .map(([key, value]) => `${key}: ${value}`)
    .join(', ')
}

const formatDate = (dateString: string | undefined) => {
  if (!dateString) return 'N/A'
  return new Date(dateString).toLocaleString()
}

// Watch filter changes and automatically re-query
watch(
  () => filterData.value.app_metadata,
  () => {
    loadUsers()
  },
  { deep: true }
)

onMounted(() => {
  loadUsers()
})
</script>

<style scoped>
.admin-users {
  padding: 24px;
  color: var(--admin-text, #374151);
}

.admin-users--dark {
  --admin-text: #f9fafb;
  --admin-border: #374151;
  --admin-bg: #1f2937;
  --admin-input-bg: #1f2937;
  --admin-card-bg: transparent;
}

.admin-users__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.admin-users__title {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
}

.admin-users__loading,
.admin-users__empty {
  text-align: center;
  padding: 48px;
  color: #9ca3af;
}

.admin-users__container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.admin-users__filter {
  padding: 16px;
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 8px;
  background: var(--admin-card-bg, white);
}

.admin-users--dark .admin-users__filter {
  border-color: #4b5563;
}

.admin-users__list {
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 8px;
  overflow: hidden;
  background: var(--admin-card-bg, white);
}

.admin-users--dark .admin-users__list {
  border-color: #4b5563;
}

.admin-users__item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px;
  border-bottom: 1px solid var(--admin-border, #e5e7eb);
  cursor: pointer;
  transition: background-color 0.15s;
}

.admin-users__item:hover {
  background: rgba(59, 130, 246, 0.05);
}

.admin-users--dark .admin-users__item {
  border-bottom-color: #4b5563;
}

.admin-users--dark .admin-users__item:hover {
  background: rgba(59, 130, 246, 0.1);
}

.admin-users__item:last-child {
  border-bottom: none;
}

.admin-users__content {
  flex: 1;
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px 24px;
  min-width: 0;
}

@media (min-width: 1024px) {
  .admin-users__content {
    grid-template-columns: repeat(4, 1fr);
  }
}

.admin-users__field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.admin-users__label {
  font-size: 11px;
  font-weight: 600;
  color: #9ca3af;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.admin-users__email {
  font-weight: 500;
  font-size: 14px;
  color: var(--admin-text, #374151);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.admin-users__id {
  font-family: monospace;
  font-size: 12px;
  color: #6b7280;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.admin-users__last-active {
  font-size: 13px;
  color: #6b7280;
}

.admin-users__metadata {
  color: #3b82f6;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>