<template>
  <div class="dashboard-container">
    <!-- Navigation Header -->
    <nav class="dashboard-nav">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between items-center h-16">
          <div class="flex items-center">
            <h1 class="dashboard-title" data-testid="dashboard-title">Dashboard</h1>
          </div>
          <div class="flex items-center space-x-4">
            <span class="dashboard-welcome" v-if="user">
              Welcome, {{ user.email }}
            </span>
            <button
              @click="handleSignOut"
              class="btn btn-secondary"
              data-testid="signout-button"
            >
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <!-- Loading State -->
      <div v-if="loading" class="dashboard-loading">
        <div class="dashboard-spinner"></div>
        <p class="dashboard-loading-text">Loading user information...</p>
      </div>

      <!-- Error State -->
      <div v-else-if="error" class="dashboard-error">
        <div class="dashboard-error-icon">
          <svg class="dashboard-error-svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 19.5c.77.833 1.732 2.5 1.732 2.5z" />
          </svg>
        </div>
        <h3 class="dashboard-error-title">Authentication Error</h3>
        <p class="dashboard-error-message">{{ error }}</p>
        <router-link to="/auth/signin" class="btn btn-primary">
          Sign In Again
        </router-link>
      </div>

      <!-- Dashboard Content -->
      <div v-else-if="user" class="space-y-8">
        <!-- Welcome Section -->
        <div class="dashboard-card">
          <h2 class="dashboard-card-title">Welcome to Your Dashboard</h2>
          <p class="dashboard-card-text">
            You have successfully authenticated with slauth. This is a protected area that requires authentication.
          </p>
        </div>

        <!-- User Information -->
        <div class="dashboard-card">
          <h3 class="dashboard-section-title">User Information</h3>
          <dl class="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
            <div>
              <dt class="dashboard-label">User ID</dt>
              <dd class="dashboard-value" data-testid="user-id">{{ user.id }}</dd>
            </div>
            <div>
              <dt class="dashboard-label">Email</dt>
              <dd class="dashboard-value" data-testid="user-email">{{ user.email }}</dd>
            </div>
            <div v-if="user.phone">
              <dt class="dashboard-label">Phone</dt>
              <dd class="dashboard-value" data-testid="user-phone">{{ user.phone }}</dd>
            </div>
            <div>
              <dt class="dashboard-label">Role</dt>
              <dd class="dashboard-value" data-testid="user-role">{{ user.role || 'authenticated' }}</dd>
            </div>
            <div>
              <dt class="dashboard-label">Created At</dt>
              <dd class="dashboard-value" data-testid="user-created-at">{{ user.created_at ? formatDate(user.created_at) : 'N/A' }}</dd>
            </div>
            <div v-if="user.last_sign_in_at">
              <dt class="dashboard-label">Last Sign In</dt>
              <dd class="dashboard-value" data-testid="user-last-signin">{{ formatDate(user.last_sign_in_at) }}</dd>
            </div>
          </dl>
        </div>

        <!-- Session Information -->
        <div class="dashboard-card" v-if="session">
          <h3 class="dashboard-section-title">Session Information</h3>
          <dl class="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
            <div>
              <dt class="dashboard-label">Token Type</dt>
              <dd class="dashboard-value" data-testid="session-token-type">{{ session.token_type }}</dd>
            </div>
            <div v-if="session.expires_at">
              <dt class="dashboard-label">Token ExpiredAt</dt>
              <dd class="dashboard-value" data-testid="session-expired-at">{{ formatExpiredAt(session.expires_at) }}</dd>
            </div>
            <div v-if="session.expires_at">
              <dt class="dashboard-label">Remaining Time</dt>
              <dd class="dashboard-value" data-testid="session-remaining-time">{{ getRemainingTime(session.expires_at) }}</dd>
            </div>
            <div>
              <dt class="dashboard-label">Expires In</dt>
              <dd class="dashboard-value" data-testid="session-expires-in">{{ session.expires_in }} seconds</dd>
            </div>
          </dl>
        </div>

        <!-- Actions -->
        <div class="dashboard-card">
          <h3 class="dashboard-section-title">Actions</h3>
          <div class="flex flex-wrap gap-4">
            <button
              @click="refreshSession"
              class="btn btn-secondary"
              data-testid="refresh-session-button"
              :disabled="refreshing"
            >
              {{ refreshing ? 'Refreshing...' : 'Refresh Session' }}
            </button>
            <router-link to="/admin" class="btn btn-secondary" data-testid="admin-link">
              Admin Panel
            </router-link>
            <router-link to="/auth" class="btn btn-secondary">
              Back to Auth
            </router-link>
          </div>
        </div>

        <!-- User Management Section -->
        <div class="dashboard-card">
          <h3 class="dashboard-section-title">Account Management</h3>
          <AuthConfig
            :auth-config="authConfig"
            :auth-client="authClient"
            :localization="localizationConfig"
            :dark-mode="false"
          >
            <UserDashboard @auth-event="handleAuthEvent" />
          </AuthConfig>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { authClient, authConfig, localizationConfig } from '@/lib/auth'
import type { User, Session } from '@cybersailor/slauth-ts'
import { UserDashboard, AuthConfig } from '@cybersailor/slauth-ui-vue'
import type { AuthEvent } from '@cybersailor/slauth-ui-vue'

const router = useRouter()

// Reactive state
const user = ref<User | null>(null)
const session = ref<Session | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)
const refreshing = ref(false)


// Load user data on component mount
onMounted(async () => {
  try {
    // Get current session
    const currentSession = authClient.getSession()

    if (!currentSession) {
      throw new Error('No active session found')
    }

    session.value = currentSession
    user.value = currentSession.user || null

    // Optionally fetch fresh user data
    const userResponse = await authClient.getUser()
    if (userResponse.user) {
      user.value = userResponse.user
    }

  } catch (err) {
    console.error('Dashboard initialization error:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load user data'
  } finally {
    loading.value = false
  }
})

// Handle sign out
const handleSignOut = async () => {
  try {
    await authClient.signOut()
    // Redirect to home page
    router.push('/')
  } catch (err) {
    console.error('Sign out failed:', err)
    // Still redirect even if sign out fails
    router.push('/')
  }
}

// Refresh session
const refreshSession = async () => {
  refreshing.value = true
  try {
    const data = await authClient.refreshSession()
    if (data.session) {
      session.value = data.session
      user.value = data.session.user || null
    }
  } catch (err) {
    console.error('Session refresh failed:', err)
    error.value = err instanceof Error ? err.message : 'Failed to refresh session'
  } finally {
    refreshing.value = false
  }
}

// Format date helper
const formatDate = (dateString: string): string => {
  try {
    return new Date(dateString).toLocaleString()
  } catch {
    return dateString
  }
}

// Format expired at time
const formatExpiredAt = (expiresAt: number): string => {
  try {
    const date = new Date(expiresAt * 1000) // expiresAt is in seconds, convert to milliseconds
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    })
  } catch {
    return 'Invalid date'
  }
}

// Get remaining time
const getRemainingTime = (expiresAt: number): string => {
  try {
    const now = Math.floor(Date.now() / 1000)
    const remaining = expiresAt - now

    if (remaining <= 0) {
      return 'Expired'
    }
    
    const hours = Math.floor(remaining / 3600)
    const minutes = Math.floor((remaining % 3600) / 60)
    const seconds = remaining % 60

    if (hours > 0) {
      return `${hours}h ${minutes}m ${seconds}s`
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`
    } else {
      return `${seconds}s`
    }
  } catch {
    return 'Calculation failed'
  }
}

// Handle auth events from user management components
const handleAuthEvent = (event: AuthEvent) => {
  console.log('Auth event received:', event)
  
  // Handle specific events that might affect the dashboard
  switch (event.event) {
    case 'profile_updated':
    case 'email_updated':
    case 'phone_updated':
      // Refresh user data when profile is updated
      refreshUserData()
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
      // If current session is revoked, redirect to sign in
      if (event.data?.session_id === session.value?.access_token) {
        router.push('/auth/signin')
      }
      break
  }
}

// Refresh user data
const refreshUserData = async () => {
  try {
    const userResponse = await authClient.getUser()
    if (userResponse.user) {
      user.value = userResponse.user
    }
  } catch (err) {
    console.error('Failed to refresh user data:', err)
  }
}
</script>

<style scoped>
/* Dashboard Container */
.dashboard-container {
  min-height: 100vh;
  background-color: var(--auth-ui-background-secondary);
}

/* Navigation */
.dashboard-nav {
  background-color: var(--auth-ui-background);
  box-shadow: var(--auth-ui-shadow-sm);
  border-bottom: 1px solid var(--auth-ui-border);
}

.dashboard-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0;
}

.dashboard-welcome {
  font-size: 0.875rem;
  color: var(--auth-ui-text-secondary);
}

/* Loading State */
.dashboard-loading {
  text-align: center;
  padding: 3rem 0;
}

.dashboard-spinner {
  display: inline-block;
  animation: spin 1s linear infinite;
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  border-bottom: 2px solid var(--auth-ui-primary);
}

.dashboard-loading-text {
  margin-top: 0.5rem;
  color: var(--auth-ui-text-secondary);
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* Error State */
.dashboard-error {
  text-align: center;
  padding: 3rem 0;
}

.dashboard-error-icon {
  color: var(--auth-ui-error);
  margin-bottom: 1rem;
}

.dashboard-error-svg {
  margin: 0 auto;
  height: 3rem;
  width: 3rem;
}

.dashboard-error-title {
  font-size: 1.125rem;
  font-weight: 500;
  color: var(--auth-ui-text);
  margin: 0 0 0.5rem 0;
}

.dashboard-error-message {
  color: var(--auth-ui-text-secondary);
  margin: 0 0 1rem 0;
}

/* Cards */
.dashboard-card {
  background-color: var(--auth-ui-background);
  border-radius: 0.5rem;
  box-shadow: var(--auth-ui-shadow-sm);
  padding: 1.5rem;
  border: 1px solid var(--auth-ui-border);
}

.dashboard-card-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--auth-ui-text);
  margin: 0 0 1rem 0;
}

.dashboard-card-text {
  color: var(--auth-ui-text-secondary);
  margin: 0;
}

.dashboard-section-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--auth-ui-text);
  margin: 0 0 1rem 0;
}

/* Labels and Values */
.dashboard-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--auth-ui-text-tertiary);
  margin: 0;
}

.dashboard-value {
  margin-top: 0.25rem;
  font-size: 0.875rem;
  color: var(--auth-ui-text);
  margin: 0;
}
</style>
