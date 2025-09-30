/**
 * Test data definitions for e2e tests
 */

export interface TestUser {
  email: string;
  password: string;
  name: string;
}

export interface ApiClientData {
  id: string;
  secret: string;
  createdAt: string;
}

export interface AuthState {
  token: string;
  tenantId: string | number;
}

export interface TestContextData {
  'auth.token': string;
  'auth.email': string;
  'auth.password': string;
  'auth.name': string;
  'tenant.id': string | number;
  'app.id': string;
  'api.client': ApiClientData;
}

/**
 * Generate unique test user data
 */
export function generateTestUser(): TestUser {
  const timestamp = Date.now();
  return {
    email: `test-${timestamp}@example.com`,
    password: 'TestPassword123!',
    name: `Test User ${timestamp}`
  };
}

/**
 * Generate unique API client data
 */
export function generateApiClientData(): Partial<ApiClientData> {
  return {
    createdAt: new Date().toISOString()
  };
}

/**
 * Default test configuration
 */
export const testConfig = {
  baseUrl: process.env.FRONTEND_URL || 'http://localhost:5180',
  mailhogUrl: 'http://localhost:8025',
  timeout: 60000,
  retries: 2
};

/**
 * Test configuration constants
 */
export const TEST_IDS = {
  // Authentication form elements
  SIGNUP_EMAIL: 'signup-email-input',
  SIGNUP_PASSWORD: 'signup-password-input',
  SIGNUP_CONFIRM_PASSWORD: 'signup-confirm-password-input',
  SIGNUP_BUTTON: 'signup-button',
  AUTH_MESSAGE: 'auth-message',

  SIGNIN_EMAIL: 'signin-email-input',
  SIGNIN_PASSWORD: 'signin-password-input',
  SIGNIN_BUTTON: 'signin-button',

  // Navigation links
  SIGNUP_LINK: 'signup-redirect-link',
  SIGNIN_LINK: 'signin-redirect-link',
  FORGOT_PASSWORD_LINK: 'forgot-password-link',

  // Social auth buttons
  GOOGLE_SIGNIN: 'google-signin-button',
  GITHUB_SIGNUP: 'github-signup-button',

  // Email verification elements
  VERIFY_OTP_PAGE: 'verify-otp-page',
  VERIFY_OTP_FORM: 'verify-otp-form',
  VERIFICATION_CODE_INPUT: 'verification-code-input',
  VERIFY_BUTTON: 'verify-button',
  RESEND_BUTTON: 'resend-button',
  BACK_TO_SIGNIN_LINK: 'back-to-signin-link',
  VERIFY_MESSAGE: 'verify-message',
  ERROR_MESSAGE: 'error-message',

  // Dashboard and user interface elements
  DASHBOARD_TITLE: 'dashboard-title',
  USER_EMAIL: 'user-email',
  USER_PROFILE: 'user-profile',
  LOGOUT_BUTTON: 'logout-button',
  SIGNOUT_BUTTON: 'signout-button',

  // Page structure elements
  AUTH_CONTAINER: 'auth-container',
  SIGNIN_FORM: 'signin-form',
  SIGNUP_FORM: 'signup-form',
  PAGE_TITLE: 'page-title',
  CONFIRMATION_STATUS: 'confirmation-status',

  // Input field containers (for nested input elements)
  SIGNIN_EMAIL_INPUT_FIELD: 'signin-email-input-field',
  SIGNIN_PASSWORD_INPUT_FIELD: 'signin-password-input-field',
  SIGNUP_EMAIL_INPUT_FIELD: 'signup-email-input-field',
  SIGNUP_PASSWORD_INPUT_FIELD: 'signup-password-input-field',
  VERIFY_OTP_EMAIL_INPUT_FIELD: 'verify-otp-email-input-field',

  // Status and message elements
  SUCCESS_MESSAGE: 'success-message',
  LOADING_INDICATOR: 'loading-indicator'
} as const;
