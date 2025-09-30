import type { AuthApi, Types } from '@cybersailor/slauth-ts'

/** Supported authentication views */
export type ViewType = 
  | 'sign_in'
  | 'sign_up' 
  | 'magic_link'
  | 'forgotten_password'
  | 'update_password'
  | 'verify_otp'

/** UI appearance themes */
export type Appearance = 'default' | 'minimal'

/** Color themes */
export type Theme = 'light' | 'dark' | 'auto'

import type { Component } from 'vue'

/** Social auth providers - support both string and component instances */
export type SocialProvider = string | Component

/** Provider component props interface */
export interface ProviderProps {
  loading?: boolean
  disabled?: boolean
  className?: string
  clientId?: string
  redirectUri?: string
  scopes?: string[]
}


/** Auth event data */
export interface AuthEvent {
  event: string
  session?: Types.Session | null
  error?: string
  email?: string
  phone?: string
  data?: any
}

/** Localization text for different views */
export interface Localization {
  sign_up?: {
    email_label?: string
    password_label?: string
    email_input_placeholder?: string
    password_input_placeholder?: string
    button_label?: string
    loading_button_label?: string
    social_provider_text?: string
    link_text?: string
    confirmation_text?: string
  }
  sign_in?: {
    email_label?: string
    password_label?: string
    email_input_placeholder?: string
    password_input_placeholder?: string
    button_label?: string
    loading_button_label?: string
    social_provider_text?: string
    link_text?: string
  }
  magic_link?: {
    email_label?: string
    email_input_label?: string
    email_input_placeholder?: string
    button_label?: string
    loading_button_label?: string
    link_text?: string
    confirmation_text?: string
  }
  forgotten_password?: {
    email_label?: string
    password_label?: string
    email_input_placeholder?: string
    button_label?: string
    loading_button_label?: string
    link_text?: string
    confirmation_text?: string
  }
  update_password?: {
    password_label?: string
    password_input_placeholder?: string
    button_label?: string
    loading_button_label?: string
    confirmation_text?: string
  }
  verify_otp?: {
    email_label?: string
    token_label?: string
    email_input_label?: string
    sms_input_label?: string
    token_input_label?: string
    email_input_placeholder?: string
    sms_input_placeholder?: string
    token_input_placeholder?: string
    button_label?: string
    loading_button_label?: string
  }
  user_profile?: {
    title?: string
    email_label?: string
    phone_label?: string
    metadata_label?: string
    save_button_label?: string
    loading_button_label?: string
    success_message?: string
  }
  password_management?: {
    title?: string
    current_password_label?: string
    new_password_label?: string
    confirm_password_label?: string
    current_password_placeholder?: string
    new_password_placeholder?: string
    confirm_password_placeholder?: string
    save_button_label?: string
    loading_button_label?: string
    success_message?: string
  }
  email_management?: {
    title?: string
    current_email_label?: string
    new_email_label?: string
    new_email_placeholder?: string
    verification_code_label?: string
    verification_code_placeholder?: string
    send_code_button_label?: string
    verify_button_label?: string
    loading_button_label?: string
    code_sent_message?: string
    success_message?: string
  }
  phone_management?: {
    title?: string
    current_phone_label?: string
    new_phone_label?: string
    new_phone_placeholder?: string
    verification_code_label?: string
    verification_code_placeholder?: string
    send_code_button_label?: string
    verify_button_label?: string
    loading_button_label?: string
    code_sent_message?: string
    success_message?: string
  }
  mfa_management?: {
    title?: string
    enroll_button_label?: string
    verify_button_label?: string
    remove_button_label?: string
    loading_button_label?: string
    qr_code_label?: string
    backup_codes_label?: string
    success_message?: string
    removed_message?: string
  }
  session_management?: {
    title?: string
    device_label?: string
    location_label?: string
    last_active_label?: string
    current_session_label?: string
    revoke_button_label?: string
    revoke_all_button_label?: string
    loading_button_label?: string
    revoked_message?: string
    all_revoked_message?: string
  }
  security_audit?: {
    title?: string
    audit_log_title?: string
    devices_title?: string
    no_events_message?: string
    no_devices_message?: string
  }
  user_dashboard?: {
    title?: string
    profile_section_title?: string
    security_section_title?: string
    sessions_section_title?: string
    audit_section_title?: string
  }
  errors?: {
    
    [errorKey: string]: string
  }
  admin?: AdminLocalization
}

/** Main Auth component props */
export interface AuthProps {
  /** slauth client instance */
  authClient: AuthApi
  /** Auth configuration */
  authConfig?: any
  /** UI appearance theme */
  appearance?: Appearance
  /** Color theme */
  theme?: Theme
  /** Redirect URL after authentication */
  redirectTo?: string
  /** Show sign up/sign in toggle links */
  showLinks?: boolean
  /** Initial view to display */
  view?: ViewType
  /** Custom localization text */
  localization?: Localization
  /** Additional CSS classes */
  className?: string
  /** Custom styles */
  style?: Record<string, string>
  /** Social providers to display */
  providers?: SocialProvider[]
  /** Only show social providers */
  onlyThirdPartyProviders?: boolean
  /** Magic link options */
  magicLink?: boolean
  /** Show forgot password link */
  showForgotPassword?: boolean
}


/** Input component props */
export interface InputProps {
  /** Input type */
  type?: 'text' | 'email' | 'password' | 'tel' | 'number'
  /** Input value */
  modelValue?: string
  /** Placeholder text */
  placeholder?: string
  /** Label text */
  label?: string
  /** Required field */
  required?: boolean
  /** Disabled state */
  disabled?: boolean
  /** Error message */
  error?: string
  /** Additional CSS classes */
  className?: string
  /** Auto-complete attribute */
  autoComplete?: string
  /** Auto-focus */
  autoFocus?: boolean
}

/** Button component props */
export interface ButtonProps {
  /** Button variant */
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'link'
  /** Button size */
  size?: 'sm' | 'md' | 'lg'
  /** Loading state */
  loading?: boolean
  /** Disabled state */
  disabled?: boolean
  /** Full width */
  fullWidth?: boolean
  /** Button type */
  type?: 'button' | 'submit' | 'reset'
  /** Additional CSS classes */
  className?: string
}

/** Message component props */
export interface MessageProps {
  /** Message type */
  type?: 'success' | 'error' | 'warning' | 'info'
  /** Message text */
  message?: string
  /** Error key for precise testing (will be added to data-error attribute) */
  errorKey?: string
  /** Additional CSS classes */
  className?: string
}

/** Label component props */
export interface LabelProps {
  /** Label text */
  text?: string
  /** Associated input ID */
  htmlFor?: string
  /** Required indicator */
  required?: boolean
  /** Additional CSS classes */
  className?: string
}

/** Anchor component props */
export interface AnchorProps {
  href: string
  /** Link text */
  text: string
  /** Additional CSS classes */
  className?: string
  /** Test ID for e2e testing */
  dataTestid?: string
}

/** Divider component props */
export interface DividerProps {
  /** Divider text */
  text?: string
  /** Additional CSS classes */
  className?: string
}

/** Theme configuration */
export interface ThemeConfig {
  /** Primary color */
  primary?: string
  /** Primary hover color */
  primaryHover?: string
  /** Background color */
  background?: string
  /** Text color */
  text?: string
  /** Border color */
  border?: string
  /** Input background */
  inputBackground?: string
  /** Error color */
  error?: string
  /** Success color */
  success?: string
  /** Border radius */
  borderRadius?: string
  /** Font family */
  fontFamily?: string
}

/** Form validation errors */
export interface FormErrors {
  email?: string
  password?: string
  confirmPassword?: string
  token?: string
  general?: string
}

/** Form state */
export interface FormState {
  loading: boolean
  errors: FormErrors
  message?: string
  messageType?: 'success' | 'error' | 'info'
  messageKey?: string
}

/** Admin localization text */
export interface AdminLocalization {
  title?: string
  dashboard?: string
  users?: string
  sessions?: string
  saml?: string
  stats?: string
  logout?: string
  user_management?: {
    title?: string
    create_user?: string
    edit_user?: string
    delete_user?: string
    reset_password?: string
    confirm_email?: string
    confirm_phone?: string
    search_placeholder?: string
    no_users?: string
  }
  session_management?: {
    title?: string
    revoke_session?: string
    revoke_all_sessions?: string
    no_sessions?: string
  }
  saml_management?: {
    title?: string
    create_provider?: string
    edit_provider?: string
    delete_provider?: string
    test_provider?: string
    no_providers?: string
  }
  system_stats?: {
    title?: string
    total_users?: string
    active_sessions?: string
    recent_signups?: string
    recent_signins?: string
  }
}
