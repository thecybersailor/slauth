<template>
  <div class="aira-user-dashboard">
    <div class="aira-user-dashboard__header">
      <h1 class="aira-user-dashboard__title">
        {{ localization.user_dashboard?.title || 'Account Settings' }}
      </h1>
    </div>

    <div class="aira-user-dashboard__content">
      <!-- Profile Information Section -->
      <div class="aira-user-dashboard__section">
        <h2 class="aira-user-dashboard__section-title">
          {{ localization.user_dashboard?.profile_section_title || 'Profile Information' }}
        </h2>
        
        <div class="aira-user-dashboard__section-content">
          <UserProfile
            @auth-event="handleAuthEvent"
            data-testid="user-profile-section"
          />
        </div>
      </div>

      <!-- Security Settings Section -->
      <div class="aira-user-dashboard__section">
        <h2 class="aira-user-dashboard__section-title">
          {{ localization.user_dashboard?.security_section_title || 'Security Settings' }}
        </h2>
        
        <div class="aira-user-dashboard__section-content">
          <div class="aira-user-dashboard__security-grid">
            <!-- Password Management -->
            <div class="aira-user-dashboard__security-item">
              <div class="aira-user-dashboard__security-card">
                <h3 class="aira-user-dashboard__security-card-title">Password</h3>
                <p class="aira-user-dashboard__security-card-description">
                  Change your account password
                </p>
                <Button
                  :variant="'outline'"
                  @click="showPasswordManagement = !showPasswordManagement"
                  data-testid="toggle-password-management"
                >
                  {{ showPasswordManagement ? 'Hide' : 'Change Password' }}
                </Button>
              </div>
              
              <div v-if="showPasswordManagement" class="aira-user-dashboard__security-form">
                <PasswordManagement
                  @auth-event="handleAuthEvent"
                  data-testid="password-management-section"
                />
              </div>
            </div>

            <!-- Email Management -->
            <div class="aira-user-dashboard__security-item">
              <div class="aira-user-dashboard__security-card">
                <h3 class="aira-user-dashboard__security-card-title">Email Address</h3>
                <p class="aira-user-dashboard__security-card-description">
                  Change your email address
                </p>
                <Button
                  :variant="'outline'"
                  @click="showEmailManagement = !showEmailManagement"
                  data-testid="toggle-email-management"
                >
                  {{ showEmailManagement ? 'Hide' : 'Change Email' }}
                </Button>
              </div>
              
              <div v-if="showEmailManagement" class="aira-user-dashboard__security-form">
                <EmailManagement
                  :current-email="currentUser?.email"
                  @auth-event="handleAuthEvent"
                  data-testid="email-management-section"
                />
              </div>
            </div>

            <!-- Phone Management -->
            <div class="aira-user-dashboard__security-item">
              <div class="aira-user-dashboard__security-card">
                <h3 class="aira-user-dashboard__security-card-title">Phone Number</h3>
                <p class="aira-user-dashboard__security-card-description">
                  Change your phone number
                </p>
                <Button
                  :variant="'outline'"
                  @click="showPhoneManagement = !showPhoneManagement"
                  data-testid="toggle-phone-management"
                >
                  {{ showPhoneManagement ? 'Hide' : 'Change Phone' }}
                </Button>
              </div>
              
              <div v-if="showPhoneManagement" class="aira-user-dashboard__security-form">
                <PhoneManagement
                  :current-phone="currentUser?.phone"
                  @auth-event="handleAuthEvent"
                  data-testid="phone-management-section"
                />
              </div>
            </div>

            <!-- MFA Management -->
            <div class="aira-user-dashboard__security-item">
              <div class="aira-user-dashboard__security-card">
                <h3 class="aira-user-dashboard__security-card-title">Two-Factor Authentication</h3>
                <p class="aira-user-dashboard__security-card-description">
                  Manage your 2FA settings
                </p>
                <Button
                  :variant="'outline'"
                  @click="showMFAManagement = !showMFAManagement"
                  data-testid="toggle-mfa-management"
                >
                  {{ showMFAManagement ? 'Hide' : 'Manage 2FA' }}
                </Button>
              </div>
              
              <div v-if="showMFAManagement" class="aira-user-dashboard__security-form">
                <MFAManagement
                  @auth-event="handleAuthEvent"
                  data-testid="mfa-management-section"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Active Sessions Section -->
      <div class="aira-user-dashboard__section">
        <h2 class="aira-user-dashboard__section-title">
          {{ localization.user_dashboard?.sessions_section_title || 'Active Sessions' }}
        </h2>
        
        <div class="aira-user-dashboard__section-content">
          <SessionManagement
            @auth-event="handleAuthEvent"
            data-testid="session-management-section"
          />
        </div>
      </div>

      <!-- Security & Audit Section -->
      <div class="aira-user-dashboard__section">
        <h2 class="aira-user-dashboard__section-title">
          {{ localization.user_dashboard?.audit_section_title || 'Security & Audit' }}
        </h2>
        
        <div class="aira-user-dashboard__section-content">
          <SecurityAudit
            @auth-event="handleAuthEvent"
            data-testid="security-audit-section"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { mergeLocalization } from '../../localization'
import type { Localization, AuthEvent } from '../../types'
import { useAuthContext } from '../../composables/useAuthContext'
import Button from '../ui/Button.vue'
import UserProfile from './UserProfile.vue'
import PasswordManagement from './PasswordManagement.vue'
import EmailManagement from './EmailManagement.vue'
import PhoneManagement from './PhoneManagement.vue'
import MFAManagement from './MFAManagement.vue'
import SessionManagement from './SessionManagement.vue'
import SecurityAudit from './SecurityAudit.vue'

interface UserDashboardProps {
  /** Custom CSS classes */
  className?: string
}

const props = defineProps<UserDashboardProps>()


const { authClient, localization: contextLocalization } = useAuthContext()

const emit = defineEmits<{
  'auth-event': [event: AuthEvent]
}>()

// UI state
const showPasswordManagement = ref(false)
const showEmailManagement = ref(false)
const showPhoneManagement = ref(false)
const showMFAManagement = ref(false)

// User data
const currentUser = ref<any>(null)

// Computed localization
const localization = computed(() => 
  mergeLocalization(contextLocalization as any)
)


// Load user data
const loadUser = async () => {
  const result = await authClient.getUser()
  currentUser.value = result.user
}

// Handle auth events from child components
const handleAuthEvent = (event: AuthEvent) => {
  // Forward the event to parent
  emit('auth-event', event)
  
  // Handle specific events
  switch (event.event) {
    case 'profile_updated':
      loadUser() // Refresh user data
      break
    case 'email_updated':
    case 'phone_updated':
      loadUser() // Refresh user data
      break
    case 'password_updated':
      // Password updated, no need to refresh user data
      break
    case 'mfa_enrolled':
    case 'mfa_unenrolled':
      // MFA status changed, components will handle their own refresh
      break
    case 'session_revoked':
    case 'all_sessions_revoked':
      // Session management components will handle their own refresh
      break
  }
}

// Load user data on mount
onMounted(() => {
  if (authClient.isAuthenticated()) {
    loadUser()
  }
})

// Watch for auth state changes
watch(() => authClient.isAuthenticated(), (isAuthenticated) => {
  if (isAuthenticated) {
    loadUser()
  } else {
    currentUser.value = null
  }
})
</script>

<style scoped>
.aira-user-dashboard {
  width: 100%;
  max-width: 72rem;
  margin: 0 auto;
}

.aira-user-dashboard__header {
  margin-bottom: 2rem;
}

.aira-user-dashboard__title {
  font-size: 1.875rem;
  font-weight: 700;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-user-dashboard__content {
  display: flex;
  flex-direction: column;
  gap: 3rem;
}

.aira-user-dashboard__section {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.aira-user-dashboard__section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  border-bottom: 1px solid var(--auth-ui-border);
  padding-bottom: 0.5rem;
  margin: 0;
}

.aira-user-dashboard__section-content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.aira-user-dashboard__security-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1.5rem;
}

.aira-user-dashboard__security-item {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-user-dashboard__security-card {
  padding: 1.5rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
  background-color: var(--auth-ui-background);
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.aira-user-dashboard__security-card-title {
  font-size: 1.125rem;
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0;
}

.aira-user-dashboard__security-card-description {
  font-size: 0.875rem;
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.aira-user-dashboard__security-form {
  padding: 1.5rem;
  border: 1px solid var(--auth-ui-border);
  border-radius: 0.5rem;
  background-color: var(--auth-ui-background-secondary);
}

/* Responsive adjustments */
@media (min-width: 1024px) {
  .aira-user-dashboard__security-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
