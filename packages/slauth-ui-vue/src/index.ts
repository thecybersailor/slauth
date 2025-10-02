// Import theme variables
import './styles/theme-variables.css'

// Main component exports
export { default as Auth } from './components/Auth.vue'
export { default as AuthConfig } from './components/AuthConfig.vue'

// Sub-component exports
export { default as SignIn } from './components/SignIn.vue'
export { default as SignUp } from './components/SignUp.vue'
export { default as MagicLink } from './components/MagicLink.vue'
export { default as ForgotPassword } from './components/ForgotPassword.vue'
export { default as UpdatePassword } from './components/UpdatePassword.vue'
export { default as VerifyOtp } from './components/VerifyOtp.vue'

// User management component exports
export * from './components/user-management'

// Admin component exports
export * from './components/admin'

// Provider components
export * from './providers'

// Form components
export { default as Input } from './components/ui/Input.vue'
export { default as Button } from './components/ui/Button.vue'
export { default as Label } from './components/ui/Label.vue'
export { default as Message } from './components/ui/Message.vue'
export { default as Divider } from './components/ui/Divider.vue'
export { default as Anchor } from './components/ui/Anchor.vue'
export { default as Drawer } from './components/ui/Drawer.vue'
export { default as Dialog } from './components/ui/Dialog.vue'

// Types
export * from './types'
export type { LocalizationConfig, AuthContext } from './components/AuthConfig.vue'
export type { AdminContext } from './composables/useAdminContext'

// Redirect management utilities
export { getPreservedParams, buildUrlWithPreservedParams, calculateRedirectUrl } from './lib/redirectManager'

// Composables
export { useAuth } from './composables/useAuth'
export { useAuthState } from './composables/useAuthState'
export { useAuthContext, useOAuthCallbackUrl, useUserRedirectUrl, useLocalization, useDarkMode } from './composables/useAuthContext'
export { useAdminContext } from './composables/useAdminContext'

// Theme and styling
export { ThemeProvider } from './theme'

// Plugin for Vue app
export { default as AiraAuthUIPlugin } from './plugin'
