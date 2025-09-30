<template>
  <div :class="['settings-management', { 'settings-management--dark': darkMode }]">
    <h2>System Configuration</h2>

    <div v-if="loading" class="loading">Loading configuration...</div>

    <div v-else>
      <!-- Basic Configuration -->
      <ConfigSection 
        title="Basic Configuration" 
        description="Configure the basic URLs and redirect settings for your authentication service."
        :defaultOpen="false"
      >
        <div class="form-group">
          <label>Site URL</label>
          <input v-model="config.site_url" type="url" placeholder="https://example.com" />
        </div>

        <div class="form-group">
          <label>Auth Service Base URL</label>
          <input v-model="config.auth_service_base_url" type="url" placeholder="https://example.com/auth" />
        </div>

        <div class="form-group">
          <label>Redirect URL Whitelist (one per line)</label>
          <textarea 
            v-model="redirectUrlsText" 
            rows="5"
            placeholder="https://example.com&#10;https://app.example.com&#10;https://*.example.com"
            @blur="updateRedirectUrls"
          ></textarea>
        </div>
      </ConfigSection>

      <!-- User Registration -->
      <ConfigSection 
        title="User Registration" 
        description="Control how users can sign up and access your application."
        :defaultOpen="false"
      >
        <CheckboxField 
          v-model="config.allow_new_users" 
          label="Allow new user registration"
          hint="If disabled, only existing users can sign in"
        />
        <CheckboxField 
          v-model="config.confirm_email" 
          label="Require email confirmation on signup"
          hint="Users must verify their email before they can sign in"
        />
        <CheckboxField 
          v-model="config.anonymous_sign_ins" 
          label="Allow anonymous sign-ins"
          hint="Users can access your app without creating an account"
        />
        <CheckboxField 
          v-model="config.enable_captcha" 
          label="Enable CAPTCHA protection"
          hint="Protect authentication endpoints from bots and abuse"
        />
      </ConfigSection>

      <!-- Advanced Settings -->
      <ConfigSection 
        title="Advanced Settings"
        description="Additional configuration options for authentication behavior."
        :defaultOpen="false"
      >
        <CheckboxField 
          v-model="config.manual_linking" 
          label="Enable manual identity linking"
          hint="Allow users to manually link multiple identity providers to their account"
        />
        <NumberField 
          v-model="maxRequestSeconds" 
          label="Maximum auth request timeout (seconds)"
          hint="Time to wait for an auth request to complete before canceling it. Recommended: 10 seconds."
          :min="1"
          :max="300"
          @update:modelValue="updateMaxRequestTimeout"
        />
      </ConfigSection>

      <!-- Multi-Factor Authentication -->
      <ConfigSection 
        title="Multi-Factor Authentication (MFA)"
        description="Configure MFA settings to enhance account security."
        :defaultOpen="false"
      >
        <NumberField 
          v-model="config.maximum_mfa_factors" 
          label="Maximum MFA factors per user"
          hint="Maximum number of MFA devices a user can register"
          :min="1"
          :max="100"
        />
        <NumberField 
          v-model="config.maximum_mfa_factor_validation_attempts" 
          label="Maximum MFA validation attempts"
          hint="Number of failed attempts before the MFA challenge is locked"
          :min="1"
          :max="10"
        />
        <SelectField
          v-model="config.mfa_update_required_aal"
          label="Required AAL for MFA updates"
          hint="Authentication Assurance Level required to modify MFA settings"
          :options="aalOptions"
        />
      </ConfigSection>

      <!-- Session Management -->
      <ConfigSection 
        title="Session Management"
        description="Configure how user sessions are created, validated, and expired."
        :defaultOpen="false"
      >
        <NumberField 
          v-model="sessionTTLSeconds.access" 
          label="Access Token TTL (seconds)"
          hint="Duration before access tokens expire. Recommended: 3600 (1 hour)"
          :min="60"
          @update:modelValue="updateSessionTTL"
        />
        <NumberField 
          v-model="sessionTTLSeconds.refresh" 
          label="Refresh Token TTL (seconds)"
          hint="Duration before refresh tokens expire. Recommended: 604800 (1 week)"
          :min="3600"
          @update:modelValue="updateSessionTTL"
        />
        <CheckboxField 
          v-model="sessionConfig.revoke_compromised_refresh_tokens" 
          label="Detect and revoke compromised refresh tokens"
          hint="Automatically revoke tokens that show signs of being compromised"
        />
        <NumberField 
          v-model="refreshTokenReuseSeconds" 
          label="Refresh token reuse interval (seconds)"
          hint="Time window where the same refresh token can be reused. Recommended: 10 seconds"
          :min="0"
          :max="300"
          @update:modelValue="updateRefreshTokenReuseInterval"
        />
        <CheckboxField 
          v-model="sessionConfig.enforce_single_session_per_user" 
          label="Enforce single session per user"
          hint="Terminate all other sessions when a user signs in from a new device"
        />
        <NumberField 
          v-model="timeBoxSessionSeconds" 
          label="Session time-box limit (seconds, 0 = never)"
          hint="Force users to re-authenticate after this duration, regardless of activity"
          :min="0"
          @update:modelValue="updateTimeBoxSessions"
        />
        <NumberField 
          v-model="inactivityTimeoutSeconds" 
          label="Inactivity timeout (seconds, 0 = never)"
          hint="Force users to re-authenticate after being inactive for this duration"
          :min="0"
          @update:modelValue="updateInactivityTimeout"
        />

        <!-- Revoke All Sessions -->
        <div class="revoke-sessions-section">
          <h4>Session Revocation</h4>
          <p class="hint-text">Force all users to sign in again by revoking all active sessions system-wide.</p>
          <button 
            @click="revokeAllSessionsConfirm" 
            :disabled="revokingAllSessions"
            class="btn-danger"
          >
            {{ revokingAllSessions ? 'Revoking...' : 'Revoke All Sessions' }}
          </button>
        </div>
      </ConfigSection>

      <!-- Rate Limiting -->
      <ConfigSection 
        title="Rate Limiting"
        description="Protect your service from abuse by limiting the rate of requests from users and IP addresses."
        :defaultOpen="false"
      >
        <RateLimitField
          v-model="rateLimitConfig.email_rate_limit"
          title="Email Rate Limit"
          :description="rateLimitConfig.email_rate_limit.description"
        />
        <RateLimitField
          v-model="rateLimitConfig.sms_rate_limit"
          title="SMS Rate Limit"
          :description="rateLimitConfig.sms_rate_limit.description"
        />
        <RateLimitField
          v-model="rateLimitConfig.sign_up_sign_in_rate_limit"
          title="Sign Up / Sign In Rate Limit"
          :description="rateLimitConfig.sign_up_sign_in_rate_limit.description"
        />
        <RateLimitField
          v-model="rateLimitConfig.token_refresh_rate_limit"
          title="Token Refresh Rate Limit"
          :description="rateLimitConfig.token_refresh_rate_limit.description"
        />
        <RateLimitField
          v-model="rateLimitConfig.token_verification_rate_limit"
          title="Token Verification Rate Limit"
          :description="rateLimitConfig.token_verification_rate_limit.description"
        />
        <RateLimitField
          v-model="rateLimitConfig.anonymous_users_rate_limit"
          title="Anonymous Users Rate Limit"
          :description="rateLimitConfig.anonymous_users_rate_limit.description"
        />
        <RateLimitField
          v-model="rateLimitConfig.web3_sign_up_sign_in_rate_limit"
          title="Web3 Sign Up / Sign In Rate Limit"
          :description="rateLimitConfig.web3_sign_up_sign_in_rate_limit.description"
        />
      </ConfigSection>

      <!-- Security Policy -->
      <ConfigSection 
        title="Security Policy"
        description="Configure advanced security settings including AAL policies and password requirements."
        :defaultOpen="false"
      >
        <div class="subsection">
          <h4>AAL (Authentication Assurance Level) Policy</h4>
          <NumberField 
            v-model="aalTimeoutMinutes" 
            label="AAL timeout (minutes)"
            hint="Duration before AAL level is automatically downgraded to AAL1. Default: 30 minutes"
            :min="1"
            :max="1440"
            @update:modelValue="updateAALTimeout"
          />
          <CheckboxField 
            v-model="securityConfig.aal_policy.allow_downgrade" 
            label="Allow AAL downgrade"
            hint="Permit automatic downgrade after the timeout period"
          />
        </div>

        <div class="subsection">
          <h4>Password Update Policy</h4>
          <SelectField
            v-model="securityConfig.password_update_config.update_required_aal"
            label="Required AAL for password updates"
            hint="Authentication level required to change password"
            :options="aalOptions"
          />
          <CheckboxField 
            v-model="securityConfig.password_update_config.revoke_other_sessions" 
            label="Revoke other sessions on password change"
            hint="Automatically sign out from all other devices when password is changed"
          />
          <RateLimitField
            v-model="securityConfig.password_update_config.rate_limit"
            title="Password Update Rate Limit"
            :description="securityConfig.password_update_config.rate_limit.description"
          />
        </div>

        <div class="subsection">
          <h4>Password Strength Requirements</h4>
          <SelectField
            v-model="securityConfig.password_strength_config.min_score"
            label="Minimum password strength score"
            hint="Using zxcvbn password strength estimation (0 = weakest, 4 = strongest)"
            :options="passwordStrengthOptions"
          />
        </div>
      </ConfigSection>

      <!-- SAML SSO Providers -->
      <ConfigSection 
        title="SAML SSO Providers"
        description="Manage SAML Single Sign-On identity providers for enterprise authentication."
        :defaultOpen="false"
      >
        <div v-if="loadingSSOProviders" class="loading-inline">Loading SSO providers...</div>
        <div v-else-if="ssoProviders.length === 0" class="empty-state">
          No SAML providers configured. Click "Add Provider" to create one.
        </div>
        <div v-else class="sso-list">
          <div
            v-for="provider in ssoProviders"
            :key="provider.id"
            class="sso-item"
          >
            <div class="sso-item__info">
              <div class="sso-item__name">{{ provider.saml_provider_name }}</div>
              <div class="sso-item__meta">
                <span>Entity ID: {{ provider.entity_id }}</span>
                <span :class="['sso-item__status', { 'sso-item__status--active': provider.enabled }]">
                  {{ provider.enabled ? '✓ Active' : '○ Inactive' }}
                </span>
              </div>
            </div>
            <div class="sso-item__actions">
              <button class="btn-sm btn-outline" @click="editSSOProvider(provider)">Edit</button>
              <button class="btn-sm btn-outline" @click="deleteSSOProviderConfirm(provider)">Delete</button>
            </div>
          </div>
        </div>
        <button class="btn-secondary" @click="openCreateSSODrawer" style="margin-top: 16px;">
          Add Provider
        </button>
      </ConfigSection>

      <!-- Save Actions -->
      <div class="actions">
        <button @click="saveConfig" :disabled="saving" class="btn-primary">
          {{ saving ? 'Saving...' : 'Save Configuration' }}
        </button>

        <button @click="loadConfig" :disabled="loading" class="btn-secondary">
          Reload
        </button>
      </div>

      <!-- Success/Error Message -->
      <div v-if="message" :class="['message', messageType]">
        {{ message }}
      </div>
    </div>

    <!-- SSO Provider Drawer -->
    <Drawer
      v-model="showSSODrawer"
      direction="rtl"
      size="600px"
      :title="isCreatingSSOProvider ? 'Create SAML Provider' : 'Edit SAML Provider'"
    >
      <div class="provider-detail">
        <div class="provider-detail__section">
          <div class="form-group">
            <label>Provider Name</label>
            <input
              v-model="ssoFormData.saml_provider_name"
              type="text"
              placeholder="Okta, Azure AD, etc."
              required
            />
          </div>
          
          <div class="form-group">
            <label>Entity ID</label>
            <input
              v-model="ssoFormData.entity_id"
              type="text"
              placeholder="https://your-idp.com/entity"
              required
            />
          </div>

          <div class="form-group">
            <label>Metadata URL (optional)</label>
            <input
              v-model="ssoFormData.metadata_url"
              type="text"
              placeholder="https://your-idp.com/metadata"
            />
          </div>

          <div class="form-group">
            <label>Metadata XML (optional)</label>
            <textarea
              v-model="ssoFormData.metadata_xml"
              rows="8"
              placeholder="<EntityDescriptor...>"
            ></textarea>
          </div>

          <label class="checkbox-label">
            <input 
              type="checkbox" 
              v-model="ssoFormData.enabled"
            />
            <span>Enable Provider</span>
          </label>
        </div>
      </div>

      <template #footer>
        <div class="provider-detail__actions">
          <button class="btn-secondary" @click="closeSSODrawer">
            Cancel
          </button>
          <button
            class="btn-primary"
            :disabled="submittingSSOProvider"
            @click="submitSSOProvider"
          >
            {{ submittingSSOProvider ? 'Saving...' : (isCreatingSSOProvider ? 'Create' : 'Update') }}
          </button>
        </div>
      </template>
    </Drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { useAdminContext } from '../../../composables/useAdminContext'
import ConfigSection from '../common/ConfigSection.vue'
import CheckboxField from '../common/CheckboxField.vue'
import NumberField from '../common/NumberField.vue'
import SelectField from '../common/SelectField.vue'
import RateLimitField from '../common/RateLimitField.vue'
import Drawer from '../../ui/Drawer.vue'

const adminContext = useAdminContext()
const adminClient = adminContext.value.adminClient
const darkMode = computed(() => adminContext.value.darkMode ?? false)

// Configuration data
const config = reactive({
  site_url: '',
  auth_service_base_url: '',
  redirect_urls: [] as string[],
  allow_new_users: true,
  manual_linking: false,
  anonymous_sign_ins: false,
  confirm_email: false,
  enable_captcha: false,
  maximum_mfa_factors: 10,
  maximum_mfa_factor_validation_attempts: 5,
  mfa_update_required_aal: 'aal1',
  max_time_allowed_for_auth_request: 10000000000,
})

const sessionConfig = reactive({
  access_token_ttl: 3600000000000,
  refresh_token_ttl: 604800000000000,
  revoke_compromised_refresh_tokens: true,
  refresh_token_reuse_interval: 10000000000,
  enforce_single_session_per_user: false,
  time_box_user_sessions: 0,
  inactivity_timeout: 0,
})

const rateLimitConfig = reactive({
  email_rate_limit: {
    max_requests: 30,
    window_duration: 3600000000000,
    description: 'Number of emails that can be sent per hour from your project',
  },
  sms_rate_limit: {
    max_requests: 150,
    window_duration: 3600000000000,
    description: 'Number of SMS messages that can be sent per hour from your project',
  },
  sign_up_sign_in_rate_limit: {
    max_requests: 30,
    window_duration: 300000000000,
    description: 'Number of sign up and sign-in requests per IP address in 5 minutes',
  },
  token_refresh_rate_limit: {
    max_requests: 30,
    window_duration: 300000000000,
    description: 'Number of sessions that can be refreshed per IP address in 5 minutes',
  },
  token_verification_rate_limit: {
    max_requests: 30,
    window_duration: 300000000000,
    description: 'Number of OTP/Magic link verifications per IP address in 5 minutes',
  },
  anonymous_users_rate_limit: {
    max_requests: 30,
    window_duration: 3600000000000,
    description: 'Number of anonymous sign-ins per hour per IP address',
  },
  web3_sign_up_sign_in_rate_limit: {
    max_requests: 30,
    window_duration: 300000000000,
    description: 'Number of Web3 sign up or sign in requests per IP address in 5 minutes',
  },
})

const securityConfig = reactive({
  aal_policy: {
    aal_timeout: 1800000000000,
    allow_downgrade: true,
  },
  password_update_config: {
    update_required_aal: 'aal2',
    revoke_other_sessions: true,
    rate_limit: {
      max_requests: 5,
      window_duration: 3600000000000,
      description: 'Password update rate limit per user',
    },
  },
  password_strength_config: {
    min_score: 2,
  },
})

// SSO Providers
const ssoProviders = ref<any[]>([])
const loadingSSOProviders = ref(false)
const showSSODrawer = ref(false)
const editingSSOProvider = ref<any>(null)
const submittingSSOProvider = ref(false)
const isCreatingSSOProvider = ref(false)

const ssoFormData = ref({
  saml_provider_name: '',
  entity_id: '',
  metadata_url: '',
  metadata_xml: '',
  enabled: true
})

// UI state
const loading = ref(false)
const saving = ref(false)
const message = ref('')
const messageType = ref<'success' | 'error'>('success')
const revokingAllSessions = ref(false)

// Redirect URLs
const redirectUrlsText = ref('')
const updateRedirectUrls = () => {
  config.redirect_urls = redirectUrlsText.value
    .split('\n')
    .map(url => url.trim())
    .filter(url => url.length > 0)
}

// Session TTL (convert nanoseconds to seconds)
const sessionTTLSeconds = reactive({
  access: 3600,
  refresh: 604800,
})

const updateSessionTTL = () => {
  sessionConfig.access_token_ttl = sessionTTLSeconds.access * 1e9
  sessionConfig.refresh_token_ttl = sessionTTLSeconds.refresh * 1e9
}

// Max request timeout
const maxRequestSeconds = ref(10)
const updateMaxRequestTimeout = (seconds: number) => {
  config.max_time_allowed_for_auth_request = seconds * 1e9
}

// Refresh token reuse interval
const refreshTokenReuseSeconds = ref(10)
const updateRefreshTokenReuseInterval = (seconds: number) => {
  sessionConfig.refresh_token_reuse_interval = seconds * 1e9
}

// Time box sessions
const timeBoxSessionSeconds = ref(0)
const updateTimeBoxSessions = (seconds: number) => {
  sessionConfig.time_box_user_sessions = seconds * 1e9
}

// Inactivity timeout
const inactivityTimeoutSeconds = ref(0)
const updateInactivityTimeout = (seconds: number) => {
  sessionConfig.inactivity_timeout = seconds * 1e9
}

// AAL timeout
const aalTimeoutMinutes = ref(30)
const updateAALTimeout = (minutes: number) => {
  securityConfig.aal_policy.aal_timeout = minutes * 60 * 1e9
}

// Options
const aalOptions = [
  { value: 'aal1', label: 'AAL1 - Single Factor' },
  { value: 'aal2', label: 'AAL2 - Multi Factor' },
  { value: 'aal3', label: 'AAL3 - Hardware Key' },
]

const passwordStrengthOptions = [
  { value: 0, label: '0 - Too Weak (not recommended)' },
  { value: 1, label: '1 - Weak' },
  { value: 2, label: '2 - Fair (recommended minimum)' },
  { value: 3, label: '3 - Strong' },
  { value: 4, label: '4 - Very Strong' },
]

// Revoke All Sessions
const revokeAllSessionsConfirm = async () => {
  if (confirm('⚠️ Are you sure you want to revoke ALL active sessions? This will log out all users system-wide.')) {
    revokingAllSessions.value = true
    const allSessions = await adminClient.listAllSessions()
    const allUserIds = [...new Set(allSessions.sessions?.map((s: any) => s.user_id) || [])]
    
    for (const userId of allUserIds) {
      await adminClient.revokeAllUserSessions(userId)
    }
    
    revokingAllSessions.value = false
    message.value = 'All sessions have been revoked successfully.'
    messageType.value = 'success'
    
    setTimeout(() => {
      message.value = ''
    }, 5000)
  }
}

// Load SSO Providers
const loadSSOProviders = async () => {
  loadingSSOProviders.value = true
  const result = await adminClient.listSAMLProviders()
  ssoProviders.value = result.providers || []
  loadingSSOProviders.value = false
}

const openCreateSSODrawer = () => {
  isCreatingSSOProvider.value = true
  editingSSOProvider.value = null
  ssoFormData.value = {
    saml_provider_name: '',
    entity_id: '',
    metadata_url: '',
    metadata_xml: '',
    enabled: true
  }
  showSSODrawer.value = true
}

const editSSOProvider = (provider: any) => {
  isCreatingSSOProvider.value = false
  editingSSOProvider.value = provider
  ssoFormData.value = {
    saml_provider_name: provider.saml_provider_name || '',
    entity_id: provider.entity_id || '',
    metadata_url: provider.metadata_url || '',
    metadata_xml: provider.metadata_xml || '',
    enabled: provider.enabled ?? true
  }
  showSSODrawer.value = true
}

const deleteSSOProviderConfirm = async (provider: any) => {
  if (confirm(`Delete SAML provider ${provider.saml_provider_name}?`)) {
    await adminClient.deleteSAMLProvider(provider.id)
    await loadSSOProviders()
  }
}

const closeSSODrawer = () => {
  showSSODrawer.value = false
  isCreatingSSOProvider.value = false
  editingSSOProvider.value = null
}

const submitSSOProvider = async () => {
  submittingSSOProvider.value = true
  
  const payload: any = {
    saml_provider_name: ssoFormData.value.saml_provider_name,
    entity_id: ssoFormData.value.entity_id,
    enabled: ssoFormData.value.enabled
  }

  if (ssoFormData.value.metadata_url) {
    payload.metadata_url = ssoFormData.value.metadata_url
  }
  
  if (ssoFormData.value.metadata_xml) {
    payload.metadata_xml = ssoFormData.value.metadata_xml
  }

  if (editingSSOProvider.value) {
    await adminClient.updateSAMLProvider(editingSSOProvider.value.id, payload)
  } else {
    await adminClient.createSAMLProvider(payload)
  }
  
  submittingSSOProvider.value = false
  closeSSODrawer()
  await loadSSOProviders()
}

// Load configuration
const loadConfig = async () => {
  loading.value = true
  message.value = ''

  const result = await adminClient.getInstanceConfig()

  // Basic config
  Object.assign(config, result.config)
  redirectUrlsText.value = (result.config.redirect_urls || []).join('\n')

  // Session config
  if (result.config.session_config) {
    Object.assign(sessionConfig, result.config.session_config)
    sessionTTLSeconds.access = Math.floor(sessionConfig.access_token_ttl / 1e9)
    sessionTTLSeconds.refresh = Math.floor(sessionConfig.refresh_token_ttl / 1e9)
    refreshTokenReuseSeconds.value = Math.floor(sessionConfig.refresh_token_reuse_interval / 1e9)
    timeBoxSessionSeconds.value = Math.floor(sessionConfig.time_box_user_sessions / 1e9)
    inactivityTimeoutSeconds.value = Math.floor(sessionConfig.inactivity_timeout / 1e9)
  }

  // Rate limit config
  if (result.config.ratelimit_config) {
    Object.assign(rateLimitConfig, result.config.ratelimit_config)
  }

  // Security config
  if (result.config.security_config) {
    Object.assign(securityConfig, result.config.security_config)
    aalTimeoutMinutes.value = Math.floor(securityConfig.aal_policy.aal_timeout / 60 / 1e9)
  }

  // Max request timeout
  maxRequestSeconds.value = Math.floor(config.max_time_allowed_for_auth_request / 1e9)

  loading.value = false
  
  // Load SSO providers
  await loadSSOProviders()
}

// Save configuration
const saveConfig = async () => {
  saving.value = true
  message.value = ''

  await adminClient.updateInstanceConfig(
    {
      ...config,
      session_config: sessionConfig,
      ratelimit_config: rateLimitConfig,
      security_config: securityConfig,
    }
  )

  message.value = 'Configuration saved successfully. Changes will take effect on all nodes within 30 seconds.'
  messageType.value = 'success'

  setTimeout(() => {
    message.value = ''
  }, 5000)

  saving.value = false
}

onMounted(() => {
  loadConfig()
})
</script>

<style scoped>
.settings-management {
  max-width: 1000px;
  margin: 0 auto;
  padding: 20px;
  color: var(--settings-text, #374151);
}

.settings-management--dark {
  --settings-text: #f9fafb;
  --settings-bg: #1f2937;
  --settings-card-bg: #374151;
  --settings-border: #4b5563;
  --settings-input-bg: #1f2937;
  --settings-input-border: #4b5563;
}

h2 {
  margin-bottom: 30px;
  color: var(--settings-text, #1a1a1a);
  font-size: 28px;
  font-weight: 600;
}

.loading {
  text-align: center;
  padding: 60px;
  color: var(--settings-text, #666);
  font-size: 16px;
}

.loading-inline {
  padding: 20px;
  text-align: center;
  color: #9ca3af;
  font-size: 14px;
}

.empty-state {
  padding: 32px;
  text-align: center;
  color: #9ca3af;
  font-size: 14px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
  color: var(--settings-text, #374151);
  font-size: 14px;
}

.form-group input[type="text"],
.form-group input[type="url"],
.form-group textarea {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--settings-input-border, #d1d5db);
  border-radius: 6px;
  font-size: 14px;
  font-family: inherit;
  transition: border-color 0.2s;
  background: var(--settings-input-bg, white);
  color: var(--settings-text, #374151);
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #3b82f6;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 16px 0;
  cursor: pointer;
  color: var(--settings-text, #374151);
}

.checkbox-label input {
  width: 16px;
  height: 16px;
}

.subsection {
  background: var(--settings-input-bg, #fff);
  border: 1px solid var(--settings-border, #e5e7eb);
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 16px;
}

.subsection h4 {
  margin: 0 0 16px 0;
  color: var(--settings-text, #374151);
  font-size: 15px;
  font-weight: 600;
}

.revoke-sessions-section {
  background: #fef2f2;
  border: 1px solid #fca5a5;
  border-radius: 6px;
  padding: 16px;
  margin-top: 24px;
}

.settings-management--dark .revoke-sessions-section {
  background: rgba(239, 68, 68, 0.1);
  border-color: #dc2626;
}

.revoke-sessions-section h4 {
  margin: 0 0 8px 0;
  color: #991b1b;
  font-size: 15px;
  font-weight: 600;
}

.settings-management--dark .revoke-sessions-section h4 {
  color: #fca5a5;
}

.hint-text {
  margin: 0 0 12px 0;
  color: #7f1d1d;
  font-size: 13px;
}

.settings-management--dark .hint-text {
  color: #fca5a5;
}

.sso-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.sso-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border: 1px solid var(--settings-border, #e5e7eb);
  border-radius: 8px;
  background: var(--settings-input-bg, white);
}

.sso-item__info {
  flex: 1;
}

.sso-item__name {
  font-weight: 500;
  margin-bottom: 4px;
  color: var(--settings-text, #374151);
}

.sso-item__meta {
  font-size: 12px;
  color: #9ca3af;
  display: flex;
  gap: 16px;
}

.sso-item__status {
  color: #9ca3af;
}

.sso-item__status--active {
  color: #10b981;
}

.sso-item__actions {
  display: flex;
  gap: 8px;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 13px;
}

.btn-outline {
  background: transparent;
  border: 1px solid var(--settings-input-border, #d1d5db);
  color: var(--settings-text, #374151);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-outline:hover {
  background: var(--settings-border, #f9fafb);
}

.actions {
  display: flex;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 2px solid var(--settings-border, #e5e7eb);
}

.btn-primary,
.btn-secondary,
.btn-danger {
  padding: 12px 24px;
  border: none;
  border-radius: 6px;
  font-size: 15px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: #3b82f6;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2563eb;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: var(--settings-input-bg, #fff);
  color: var(--settings-text, #374151);
  border: 1px solid var(--settings-input-border, #d1d5db);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--settings-border, #f9fafb);
}

.btn-secondary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-danger {
  background: #ef4444;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #dc2626;
}

.btn-danger:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.message {
  padding: 14px 18px;
  margin-top: 20px;
  border-radius: 6px;
  font-size: 14px;
  line-height: 1.5;
}

.message.success {
  background: #d1fae5;
  color: #065f46;
  border: 1px solid #6ee7b7;
}

.message.error {
  background: #fee2e2;
  color: #991b1b;
  border: 1px solid #fca5a5;
}

.provider-detail {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.provider-detail__section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.provider-detail__actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}
</style>