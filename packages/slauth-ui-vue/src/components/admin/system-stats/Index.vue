<template>
  <div :class="['admin-stats', { 'admin-stats--dark': darkMode }]">
    <h2 class="admin-stats__title">{{ t.title || 'System Statistics' }}</h2>

    <div v-if="loading" class="admin-stats__loading">Loading...</div>

    <div v-else class="admin-stats__grid">
      <div class="admin-stats__card" data-testid="admin-stats-total-users">
        <div class="admin-stats__card-icon">👥</div>
        <div class="admin-stats__card-content">
          <div class="admin-stats__card-label">{{ t.total_users || 'Total Users' }}</div>
          <div class="admin-stats__card-value">{{ stats.totalUsers }}</div>
        </div>
      </div>

      <div class="admin-stats__card" data-testid="admin-stats-active-sessions">
        <div class="admin-stats__card-icon">🔐</div>
        <div class="admin-stats__card-content">
          <div class="admin-stats__card-label">{{ t.active_sessions || 'Active Sessions' }}</div>
          <div class="admin-stats__card-value">{{ stats.activeSessions }}</div>
        </div>
      </div>

      <div class="admin-stats__card" data-testid="admin-stats-recent-signups">
        <div class="admin-stats__card-icon">📝</div>
        <div class="admin-stats__card-content">
          <div class="admin-stats__card-label">{{ t.recent_signups || 'Signups (24h)' }}</div>
          <div class="admin-stats__card-value">{{ stats.recentSignups }}</div>
        </div>
      </div>

      <div class="admin-stats__card" data-testid="admin-stats-recent-signins">
        <div class="admin-stats__card-icon">🚪</div>
        <div class="admin-stats__card-content">
          <div class="admin-stats__card-label">{{ t.recent_signins || 'Signins (24h)' }}</div>
          <div class="admin-stats__card-value">{{ stats.recentSignins }}</div>
        </div>
      </div>

      <div class="admin-stats__card" data-testid="admin-stats-email-verified">
        <div class="admin-stats__card-icon">✉️</div>
        <div class="admin-stats__card-content">
          <div class="admin-stats__card-label">Email Verified</div>
          <div class="admin-stats__card-value">{{ stats.emailVerified }}</div>
        </div>
      </div>

      <div class="admin-stats__card" data-testid="admin-stats-mfa-enabled">
        <div class="admin-stats__card-icon">🔒</div>
        <div class="admin-stats__card-content">
          <div class="admin-stats__card-label">MFA Enabled</div>
          <div class="admin-stats__card-value">{{ stats.mfaEnabled }}</div>
        </div>
      </div>
    </div>

    <div class="admin-stats__actions">
      <Button
        variant="outline"
        data-testid="admin-stats-refresh-button"
        @click="loadStats"
      >
        Refresh Stats
      </Button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'
import Button from '../../ui/Button.vue'

const adminContext = useAdminContext()
const adminClient = adminContext.value.adminClient
const darkMode = computed(() => adminContext.value.darkMode ?? false)

const t = computed(() => adminContext.value.localization?.admin?.system_stats || {})

const loading = ref(false)
const stats = ref({
  totalUsers: 0,
  activeSessions: 0,
  recentSignups: 0,
  recentSignins: 0,
  emailVerified: 0,
  mfaEnabled: 0
})

const loadStats = async () => {
  loading.value = true
  
  // Use dedicated statistics API
  const [userCountResult, sessionStatsResult, signupsResult, signinsResult, usersResult] = await Promise.all([
    adminClient.getUserCount(),
    adminClient.getActiveSessionCount(),
    adminClient.getRecentSignups(),
    adminClient.getRecentSignins(),
    adminClient.listUsers()
  ])
  
  const users = usersResult.users || []
  
  stats.value = {
    totalUsers: userCountResult.count || 0,
    activeSessions: sessionStatsResult.active_sessions || 0,
    recentSignups: signupsResult.count || 0,
    recentSignins: signinsResult.count || 0,
    emailVerified: users.filter((u: any) => u.email_confirmed).length,
    mfaEnabled: 0 // Backend MFA statistics support needed
  }
  
  loading.value = false
}

onMounted(() => {
  loadStats()
})
</script>

<style scoped>
.admin-stats {
  padding: 24px;
  color: var(--admin-text, #374151);
}

.admin-stats--dark {
  --admin-text: #f9fafb;
  --admin-border: #374151;
  --admin-bg: #1f2937;
  --admin-card-bg: #374151;
}

.admin-stats__title {
  margin: 0 0 24px 0;
  font-size: 24px;
  font-weight: 600;
}

.admin-stats__loading {
  text-align: center;
  padding: 48px;
  color: #9ca3af;
}

.admin-stats__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.admin-stats__card {
  display: flex;
  align-items: center;
  padding: 20px;
  border: 1px solid var(--admin-border, #e5e7eb);
  border-radius: 8px;
  background: var(--admin-card-bg, white);
  transition: box-shadow 0.2s;
}

.admin-stats__card:hover {
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.admin-stats__card-icon {
  font-size: 32px;
  margin-right: 16px;
}

.admin-stats__card-content {
  flex: 1;
}

.admin-stats__card-label {
  font-size: 14px;
  color: #9ca3af;
  margin-bottom: 4px;
}

.admin-stats__card-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--admin-text, #374151);
}

.admin-stats__actions {
  text-align: center;
  padding-top: 16px;
  border-top: 1px solid var(--admin-border, #e5e7eb);
}
</style>