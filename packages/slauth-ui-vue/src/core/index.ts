/**
 * Core UI components and composables export
 * Pure UI layer without backend dependencies
 */

// ==================== Adapter Types (Core) ====================
export type {
  AuthAdapter,
  AuthResult,
  Session,
  User,
  SignInOptions,
  SignUpOptions,
  OAuthSignInParams,
  OAuthResult
} from './adapters/types'

// ==================== Components ====================
export { default as Auth } from '../components/Auth.vue'
export { default as AuthConfig } from '../components/AuthConfig.vue'
export { default as SignIn } from '../components/SignIn.vue'
export { default as SignUp } from '../components/SignUp.vue'
export { default as MagicLink } from '../components/MagicLink.vue'
export { default as ForgotPassword } from '../components/ForgotPassword.vue'
export { default as UpdatePassword } from '../components/UpdatePassword.vue'
export { default as VerifyOtp } from '../components/VerifyOtp.vue'
export { default as SocialProviders } from '../components/SocialProviders.vue'

// ==================== UI Components ====================
export { default as Input } from '../components/ui/Input.vue'
export { default as Button } from '../components/ui/Button.vue'
export { default as Label } from '../components/ui/Label.vue'
export { default as Message } from '../components/ui/Message.vue'
export { default as Divider } from '../components/ui/Divider.vue'
export { default as Anchor } from '../components/ui/Anchor.vue'
export { default as Drawer } from '../components/ui/Drawer.vue'
export { default as Dialog } from '../components/ui/Dialog.vue'
export { default as SocialButton } from '../components/ui/SocialButton.vue'
export { default as Table } from '../components/ui/Table.vue'
export { default as JsonEditor } from '../components/ui/JsonEditor.vue'
export { default as Section } from '../components/ui/Section.vue'
export { default as SessionTable } from '../components/ui/SessionTable.vue'

// ==================== User Management Components ====================
export * from '../components/user-management'

// ==================== Admin Components ====================
export * from '../components/admin'

// ==================== Composables ====================
export { useAuth } from '../composables/useAuth'
export { useAuthState, createAuthState } from '../composables/useAuthState'
export { useAuthContext, useOAuthCallbackUrl, useUserRedirectUrl, useLocalization, useDarkMode } from '../composables/useAuthContext'
export { useAdminContext } from '../composables/useAdminContext'
export { useOAuthSignIn } from '../composables/useOAuthSignIn'
export { useAuthPaths } from '../composables/useAuthPaths'
export { useErrorHandler } from '../composables/useErrorHandler'
export { useOAuthButtonStyles } from '../composables/useOAuthButtonStyles'

// ==================== Types ====================
export * from '../types'
export type { 
  LocalizationConfig, 
  AuthContext, 
  AppearanceConfig
} from '../components/AuthConfig.vue'
// Note: AuthConfig type is available via typeof AuthConfig or import from '../components/AuthConfig.vue'
export type { AdminContext } from '../composables/useAdminContext'

// ==================== Utilities ====================
export { getPreservedParams, buildUrlWithPreservedParams, calculateRedirectUrl } from '../lib/redirectManager'

// ==================== Theme ====================
export { ThemeProvider, useTheme, generateCSSVariables, defaultTheme } from '../theme'
export type { ThemeVariables, ThemeConfig } from '../theme'

// ==================== Providers ====================
export * from '../providers'

// ==================== Plugin ====================
export { default as AiraAuthUIPlugin } from '../plugin'
