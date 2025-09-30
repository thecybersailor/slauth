import type { Localization } from '../types'

/** Default English localization */
export const defaultLocalization: Required<Localization> = {
  sign_up: {
    email_label: 'Email address',
    password_label: 'Create a Password',
    email_input_placeholder: 'Your email address',
    password_input_placeholder: 'Your password',
    button_label: 'Sign up',
    loading_button_label: 'Signing up ...',
    social_provider_text: 'Sign up with {{provider}}',
    link_text: 'Already have an account? Sign in',
    confirmation_text: 'Check your email for the confirmation link'
  },
  sign_in: {
    email_label: 'Email address',
    password_label: 'Password',
    email_input_placeholder: 'Your email address',
    password_input_placeholder: 'Your password',
    button_label: 'Sign in',
    loading_button_label: 'Signing in ...',
    social_provider_text: 'Sign in with {{provider}}',
    link_text: "Don't have an account? Sign up"
  },
  magic_link: {
    email_input_label: 'Email address',
    email_input_placeholder: 'Your email address',
    button_label: 'Send magic link',
    loading_button_label: 'Sending magic link ...',
    link_text: 'Sign in with password instead',
    confirmation_text: 'Check your email for the magic link'
  },
  forgotten_password: {
    email_label: 'Email address',
    password_label: 'Password',
    email_input_placeholder: 'Your email address',
    button_label: 'Send reset instructions',
    loading_button_label: 'Sending reset instructions ...',
    link_text: 'Remember your password? Sign in',
    confirmation_text: 'Check your email for the password reset link'
  },
  update_password: {
    password_label: 'New password',
    password_input_placeholder: 'Your new password',
    button_label: 'Update password',
    loading_button_label: 'Updating password ...',
    confirmation_text: 'Your password has been updated'
  },
  verify_otp: {
    email_input_label: 'Email address',
    sms_input_label: 'Phone number',
    token_input_label: 'Verification code',
    email_input_placeholder: 'Your email address',
    sms_input_placeholder: 'Your phone number',
    token_input_placeholder: 'Your verification code',
    button_label: 'Verify',
    loading_button_label: 'Verifying ...'
  },
  user_profile: {
    title: 'Profile',
    email_label: 'Email address',
    phone_label: 'Phone number',
    metadata_label: 'Additional information',
    save_button_label: 'Save changes',
    loading_button_label: 'Saving ...',
    success_message: 'Profile updated successfully'
  },
  password_management: {
    title: 'Change Password',
    current_password_label: 'Current password',
    new_password_label: 'New password',
    confirm_password_label: 'Confirm new password',
    current_password_placeholder: 'Enter current password',
    new_password_placeholder: 'Enter new password',
    confirm_password_placeholder: 'Confirm new password',
    save_button_label: 'Update password',
    loading_button_label: 'Updating password ...',
    success_message: 'Password updated successfully'
  },
  email_management: {
    title: 'Change Email',
    current_email_label: 'Current email',
    new_email_label: 'New email address',
    new_email_placeholder: 'Enter new email address',
    verification_code_label: 'Verification code',
    verification_code_placeholder: 'Enter verification code',
    send_code_button_label: 'Send verification code',
    verify_button_label: 'Verify email',
    loading_button_label: 'Processing ...',
    code_sent_message: 'Verification code sent to your new email',
    success_message: 'Email updated successfully'
  },
  phone_management: {
    title: 'Change Phone Number',
    current_phone_label: 'Current phone number',
    new_phone_label: 'New phone number',
    new_phone_placeholder: 'Enter new phone number',
    verification_code_label: 'Verification code',
    verification_code_placeholder: 'Enter verification code',
    send_code_button_label: 'Send verification code',
    verify_button_label: 'Verify phone',
    loading_button_label: 'Processing ...',
    code_sent_message: 'Verification code sent to your new phone',
    success_message: 'Phone number updated successfully'
  },
  mfa_management: {
    title: 'Two-Factor Authentication',
    enroll_button_label: 'Set up 2FA',
    verify_button_label: 'Verify',
    remove_button_label: 'Remove',
    loading_button_label: 'Processing ...',
    qr_code_label: 'Scan this QR code with your authenticator app',
    backup_codes_label: 'Backup codes',
    success_message: '2FA enabled successfully',
    removed_message: '2FA disabled successfully'
  },
  session_management: {
    title: 'Active Sessions',
    device_label: 'Device',
    location_label: 'Location',
    last_active_label: 'Last active',
    current_session_label: 'Current session',
    revoke_button_label: 'Revoke',
    revoke_all_button_label: 'Revoke all sessions',
    loading_button_label: 'Processing ...',
    revoked_message: 'Session revoked successfully',
    all_revoked_message: 'All sessions revoked successfully'
  },
  security_audit: {
    title: 'Security & Audit',
    audit_log_title: 'Security Events',
    devices_title: 'Trusted Devices',
    no_events_message: 'No security events found',
    no_devices_message: 'No trusted devices found'
  },
  user_dashboard: {
    title: 'Account Settings',
    profile_section_title: 'Profile Information',
    security_section_title: 'Security Settings',
    sessions_section_title: 'Active Sessions',
    audit_section_title: 'Security & Audit'
  },
  errors: {},
  admin: {
    title: 'Admin Panel',
    dashboard: 'Dashboard',
    users: 'Users',
    sessions: 'Sessions',
    saml: 'SAML SSO',
    stats: 'Statistics',
    logout: 'Logout',
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

/** Merge custom localization with defaults */
export function mergeLocalization(custom?: Localization): Required<Localization> {
  if (!custom) return defaultLocalization

  return {
    sign_up: { ...defaultLocalization.sign_up, ...custom.sign_up },
    sign_in: { ...defaultLocalization.sign_in, ...custom.sign_in },
    magic_link: { ...defaultLocalization.magic_link, ...custom.magic_link },
    forgotten_password: { ...defaultLocalization.forgotten_password, ...custom.forgotten_password },
    update_password: { ...defaultLocalization.update_password, ...custom.update_password },
    verify_otp: { ...defaultLocalization.verify_otp, ...custom.verify_otp },
    user_profile: { ...defaultLocalization.user_profile, ...custom.user_profile },
    password_management: { ...defaultLocalization.password_management, ...custom.password_management },
    email_management: { ...defaultLocalization.email_management, ...custom.email_management },
    phone_management: { ...defaultLocalization.phone_management, ...custom.phone_management },
    mfa_management: { ...defaultLocalization.mfa_management, ...custom.mfa_management },
    session_management: { ...defaultLocalization.session_management, ...custom.session_management },
    security_audit: { ...defaultLocalization.security_audit, ...custom.security_audit },
    user_dashboard: { ...defaultLocalization.user_dashboard, ...custom.user_dashboard },
    errors: { ...defaultLocalization.errors, ...custom.errors },
    admin: { ...defaultLocalization.admin, ...custom.admin }
  }
}

/** Replace template variables in text */
export function interpolate(text: string, variables: Record<string, string>): string {
  return text.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    return variables[key] || match
  })
}

/** Get provider display name */
export function getProviderDisplayName(provider: string): string {
  const providerNames: Record<string, string> = {
    google: 'Google',
    github: 'GitHub',
    facebook: 'Facebook',
    apple: 'Apple',
    discord: 'Discord',
    twitter: 'Twitter',
    linkedin: 'LinkedIn',
    microsoft: 'Microsoft',
    gitlab: 'GitLab',
    bitbucket: 'Bitbucket'
  }

  return providerNames[provider] || provider.charAt(0).toUpperCase() + provider.slice(1)
}

/**
 */
export function formatError(error: any, localization?: Required<Localization>): string {
  if (!error || typeof error !== 'object') {
    return 'An error occurred'
  }

  const { key, message, trace_id, is_system_error } = error

  
  if (is_system_error && trace_id) {
    return `${message || 'System error occurred'}. Trace ID: ${trace_id}`
  }

  
  if (localization && key && localization.errors?.[key]) {
    return localization.errors[key]
  }

  
  return message || 'An error occurred'
}
