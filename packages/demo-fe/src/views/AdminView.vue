<template>
  <div>
    <AdminLayout
      :admin-client="adminClient"
      :dark-mode="isDarkMode"
      :localization="localization"
    >
      <template #user-filter="{ app_metadata }">
        <div class="user-filter">
          <div class="user-filter__field">
            <label class="user-filter__label">Level:</label>
            <input 
              v-model="app_metadata.level" 
              class="user-filter__input"
              placeholder="admin, user, guest..."
            />
          </div>
          <div class="user-filter__field">
            <label class="user-filter__label">Role:</label>
            <input 
              v-model="app_metadata.role" 
              class="user-filter__input"
              placeholder="manager, developer..."
            />
          </div>
        </div>
      </template>
    </AdminLayout>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { AdminLayout } from '@cybersailor/slauth-ui-vue'
import { authClient, adminClient } from '../lib/auth'
import { useRouter } from 'vue-router'

const router = useRouter()


const session = authClient.getSession()
if (session) {
  adminClient.setSession(session)
}


const updateDarkMode = () => {
  const theme = document.documentElement.getAttribute('data-theme')
  return theme === 'dark'
}


const isDarkMode = ref(updateDarkMode())


let observer: MutationObserver | null = null

onMounted(() => {
  
  isDarkMode.value = updateDarkMode()
  
  
  observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'attributes' && mutation.attributeName === 'data-theme') {
        isDarkMode.value = updateDarkMode()
      }
    })
  })
  
  
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme']
  })
})

onUnmounted(() => {
  
  if (observer) {
    observer.disconnect()
  }
})


const localization = {
  admin: {
    title: 'slauth Admin',
    dashboard: 'Dashboard',
    users: 'User Management',
    sessions: 'Session Management',
    saml: 'SAML SSO',
    stats: 'Statistics',
    logout: 'Sign Out',
    user_management: {
      title: 'User Management',
      create_user: 'Create User',
      edit_user: 'Edit User',
      delete_user: 'Delete User',
      reset_password: 'Reset Password',
      confirm_email: 'Confirm Email',
      confirm_phone: 'Confirm Phone',
      search_placeholder: 'Search users...',
      no_users: 'No users found'
    },
    session_management: {
      title: 'Session Management',
      revoke_session: 'Revoke Session',
      revoke_all_sessions: 'Revoke All Sessions',
      no_sessions: 'No sessions found'
    },
    saml_management: {
      title: 'SAML SSO Management',
      create_provider: 'Create Provider',
      edit_provider: 'Edit Provider',
      delete_provider: 'Delete Provider',
      test_provider: 'Test Provider',
      no_providers: 'No SAML providers found'
    },
    system_stats: {
      title: 'System Statistics',
      total_users: 'Total Users',
      active_sessions: 'Active Sessions',
      recent_signups: 'Recent Signups',
      recent_signins: 'Recent Signins'
    }
  }
}
</script>

<style scoped>
.user-filter {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.user-filter__field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
  min-width: 200px;
}

.user-filter__label {
  font-size: 14px;
  font-weight: 500;
  color: var(--admin-text, #374151);
}

.user-filter__input {
  padding: 8px 12px;
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.2s;
  background: var(--admin-input-bg, white);
  color: var(--admin-text, #374151);
}

.user-filter__input:focus {
  outline: none;
  border-color: #3b82f6;
}
</style>
