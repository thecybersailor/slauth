<template>
  <div class="auth-config-provider">
    <slot />
  </div>
</template>

<script setup lang="ts">
import { provide, computed } from 'vue'
import type { AuthApi } from '@cybersailor/slauth-ts'

// UI appearance configuration interface
export interface AppearanceConfig {
  theme?: 'light' | 'dark' | 'auto'
  variables?: {
    default?: Record<string, any>
  }
}

// AuthConfig interface definition
export interface AuthConfig {
  // Service endpoint configuration
  authBaseUrl: string

  // Social login providers
  providers?: string[]

  // Redirect configuration
  redirectTo?: string
  followRedirect?: boolean

  // UI appearance configuration
  appearance?: 'default' | 'minimal' | AppearanceConfig

  // Feature toggles
  magicLink?: boolean
  showForgotPassword?: boolean
  onlyThirdPartyProviders?: boolean
  showLinks?: boolean

  // OAuth provider configuration
  googleClientId?: string
  facebookClientId?: string
  scope?: string

  // Debug mode
  debug?: boolean
}


export interface LocalizationConfig {
  variables?: {
    sign_in?: {
      email_label?: string
      password_label?: string
      button_label?: string
      loading_button_label?: string
      social_provider_text?: string
      link_text?: string
    }
    sign_up?: {
      email_label?: string
      password_label?: string
      button_label?: string
      loading_button_label?: string
      social_provider_text?: string
      link_text?: string
    }
    magic_link?: {
      email_label?: string
      button_label?: string
      loading_button_label?: string
      link_text?: string
      confirmation_text?: string
    }
    forgotten_password?: {
      email_label?: string
      button_label?: string
      loading_button_label?: string
      link_text?: string
      confirmation_text?: string
    }
    update_password?: {
      password_label?: string
      button_label?: string
      loading_button_label?: string
      confirmation_text?: string
    }
    verify_otp?: {
      email_label?: string
      token_label?: string
      button_label?: string
      loading_button_label?: string
    }
  }
}

// Complete authentication context interface
export interface AuthContext {
  authClient: AuthApi
  authConfig: AuthConfig
  localization?: LocalizationConfig
  darkMode?: boolean
}

// Props definition
interface AuthConfigProps {
  authConfig: AuthConfig
  authClient: AuthApi
  localization?: LocalizationConfig
  darkMode?: boolean
}

const props = withDefaults(defineProps<AuthConfigProps>(), {
  localization: () => ({}),
  darkMode: false
})

// Create complete authentication context
const authContext = computed<AuthContext>(() => ({
  authClient: props.authClient,
  authConfig: props.authConfig,
  localization: props.localization,
  darkMode: props.darkMode
}))

// Provide to child components
provide('auth-context', authContext)
</script>

<style scoped>
.auth-config-provider {
  /* Transparent container, does not affect layout */
}
</style>
