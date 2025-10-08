/* eslint-disable */
/* tslint:disable */
// @ts-nocheck
/*
 * ---------------------------------------------------------------
 * ## THIS FILE WAS GENERATED VIA SWAGGER-TYPESCRIPT-API        ##
 * ##                                                           ##
 * ## AUTHOR: acacode                                           ##
 * ## SOURCE: https://github.com/acacode/swagger-typescript-api ##
 * ---------------------------------------------------------------
 */

/** @format int64 */
export enum TimeDuration {
  MinDuration = -9223372036854776000,
  MaxDuration = 9223372036854776000,
  Nanosecond = 1,
  Microsecond = 1000,
  Millisecond = 1000000,
  Second = 1000000000,
  Minute = 60000000000,
  Hour = 3600000000000,
}

export enum FactorType {
  FactorTypeTOTP = "totp",
  FactorTypeWebAuthn = "webauthn",
  FactorTypePhone = "phone",
}

export enum FactorStatus {
  FactorStatusUnverified = "unverified",
  FactorStatusVerified = "verified",
}

export enum AALLevel {
  AALLevel1 = "aal1",
  AALLevel2 = "aal2",
  AALLevel3 = "aal3",
}

export interface GithubComThecybersailorSlauthPkgConfigAALPolicy {
  aaltimeout?: TimeDuration;
  allowDowngrade?: boolean;
}

export interface GithubComThecybersailorSlauthPkgConfigAuthServiceConfig {
  /** If this is disabled, new users will not be able to sign up to your application */
  allow_new_users?: boolean;
  /** Enable anonymous sign-ins for your project */
  anonymous_sign_ins?: boolean;
  auth_service_base_url?: string;
  /** Users will need to confirm their email address before signing in for the first time */
  confirm_email?: boolean;
  /**
   * Enable Captcha protection
   * Protect authentication endpoints from bots and abuse.
   */
  enable_captcha?: boolean;
  /** Enable manual linking APIs for your project */
  manual_linking?: boolean;
  /**
   * Maximum time allowed for an Auth request to last
   * Number of seconds to wait for an Auth request to complete before canceling it.
   * In certain high-load situations setting a larger or smaller value can be used
   * to control load-shedding. Recommended: 10 seconds.
   */
  max_time_allowed_for_auth_request?: TimeDuration;
  /** Maximum number of attempts to validate an MFA factor */
  maximum_mfa_factor_validation_attempts?: number;
  /** Maximum number of per-user MFA factors */
  maximum_mfa_factors?: number;
  mfa_update_required_aal?: AALLevel;
  /** Rate limiting configuration */
  ratelimit_config?: GithubComThecybersailorSlauthPkgConfigRatelimitConfig;
  /**
   * Redirect URLs
   * URLs that auth providers are permitted to redirect to post authentication. Wildcards are allowed, for example, https://*.instance.com
   */
  redirect_urls?: string[];
  /** Security configuration */
  security_config?: GithubComThecybersailorSlauthPkgConfigSecurityConfig;
  /** Session configuration */
  session_config?: GithubComThecybersailorSlauthPkgConfigSessionConfig;
  /**
   * Site URL
   * Configure the default redirect URL used when a redirect URL is not specified or doesn't match one from the allow list. This value is also exposed as a template variable in the email templates section. Wildcards cannot be used here.
   */
  site_url?: string;
}

export interface GithubComThecybersailorSlauthPkgConfigPasswordStrengthConfig {
  minScore?: number;
}

export interface GithubComThecybersailorSlauthPkgConfigPasswordUpdateConfig {
  rateLimit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  revokeOtherSessions?: boolean;
  updateRequiredAAL?: AALLevel;
}

export interface GithubComThecybersailorSlauthPkgConfigRateLimit {
  /** Description provides context about what this rate limit applies to */
  description?: string;
  /** MaxRequests is the maximum number of requests allowed */
  max_requests?: number;
  /** WindowDuration is the time window for the rate limit */
  window_duration?: TimeDuration;
}

export interface GithubComThecybersailorSlauthPkgConfigRatelimitConfig {
  /** Anonymous users rate limiting */
  anonymous_users_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  /** Email rate limiting */
  email_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  /** Sign up and sign in rate limiting */
  sign_up_sign_in_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  /** SMS rate limiting */
  sms_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  /** Token refresh rate limiting */
  token_refresh_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  /** Token verification rate limiting */
  token_verification_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  /** Web3 sign up and sign in rate limiting */
  web3_sign_up_sign_in_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
}

export interface GithubComThecybersailorSlauthPkgConfigSecurityConfig {
  aalpolicy?: GithubComThecybersailorSlauthPkgConfigAALPolicy;
  passwordStrengthConfig?: GithubComThecybersailorSlauthPkgConfigPasswordStrengthConfig;
  passwordUpdateConfig?: GithubComThecybersailorSlauthPkgConfigPasswordUpdateConfig;
}

export interface GithubComThecybersailorSlauthPkgConfigSessionConfig {
  /**
   * Access token TTL (in seconds)
   * The time-to-live (TTL) for access tokens. Recommendation: 1 hour.
   */
  access_token_ttl?: number;
  /**
   * Enforce single session per user
   * If enabled, all but a user's most recently active session will be terminated.
   */
  enforce_single_session_per_user?: boolean;
  /**
   * Inactivity timeout (in seconds)
   * The amount of time a user needs to be inactive to be forced to sign in again. Use 0 for never.
   */
  inactivity_timeout?: number;
  /**
   * Refresh token reuse interval (in seconds)
   * Time interval where the same refresh token can be used multiple times
   * to request for an access token. Recommendation: 10 seconds.
   */
  refresh_token_reuse_interval?: number;
  /**
   * Refresh token TTL (in seconds)
   * The time-to-live (TTL) for refresh tokens. Recommendation: 1 week.
   */
  refresh_token_ttl?: number;
  /**
   * Detect and revoke potentially compromised refresh tokens
   * Prevent replay attacks from potentially compromised refresh tokens.
   */
  revoke_compromised_refresh_tokens?: boolean;
  /**
   * Time-box user sessions (in seconds)
   * The amount of time before a user is forced to sign in again. Use 0 for never.
   */
  time_box_user_sessions?: number;
}

export interface AdminCreateUserRequest {
  app_metadata?: Record<string, any>;
  email?: string;
  email_confirmed?: boolean;
  password?: string;
  phone?: string;
  phone_confirmed?: boolean;
  user_data?: Record<string, any>;
  user_metadata?: Record<string, any>;
}

export interface AdminResetPasswordRequest {
  new_password?: string;
}

export interface AdminUpdateUserRequest {
  app_metadata?: Record<string, any>;
  banned_until?: string;
  email?: string;
  email_confirmed?: boolean;
  phone?: string;
  phone_confirmed?: boolean;
  user_data?: Record<string, any>;
}

export interface AdminUserResponse {
  aal?: any;
  app_metadata?: Record<string, any>;
  /** @example "authenticated" */
  aud?: string;
  banned_until?: string;
  /** @example "2023-01-01T00:00:00Z" */
  confirmed_at?: string;
  /** @example "2023-01-01T00:00:00Z" */
  created_at?: string;
  /** @example "user@example.com" */
  email?: string;
  email_confirmed?: boolean;
  /** @example "2023-01-01T00:00:00Z" */
  email_confirmed_at?: string;
  factors?: Factor[];
  /** @example "user_123" */
  id?: string;
  identities?: UserIdentity[];
  is_anonymous?: boolean;
  /** @example "2023-01-01T00:00:00Z" */
  last_sign_in_at?: string;
  /** @example "+1234567890" */
  phone?: string;
  phone_confirmed?: boolean;
  /** @example "2023-01-01T00:00:00Z" */
  phone_confirmed_at?: string;
  /** @example "user" */
  role?: string;
  /** @example "2023-01-01T00:00:00Z" */
  updated_at?: string;
  user_metadata?: Record<string, any>;
}

export interface CreateSAMLProviderRequest {
  enabled?: boolean;
  name: string;
}

export interface Factor {
  created_at?: string;
  friendly_name?: string;
  id?: string;
  status?: FactorStatus;
  type?: FactorType;
  updated_at?: string;
}

export interface GetInstanceConfigResponse {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfig;
  instance_id?: string;
}

export interface ListSAMLProvidersResponse {
  page?: number;
  page_size?: number;
  providers?: SAMLProviderResponse[];
  total?: number;
}

export interface ListSessionsResponse {
  page?: number;
  page_size?: number;
  sessions?: SessionResponse[];
  total?: number;
}

export interface ListUsersResponse {
  page?: number;
  page_size?: number;
  total?: number;
  users?: AdminUserResponse[];
}

export interface QueryPagination {
  page?: number;
  pageSize?: number;
}

export interface QueryUsersRequest {
  filters?: Record<string, any>;
  pagination?: QueryPagination;
  sort?: string[];
}

export interface SAMLProviderResponse {
  created_at?: string;
  enabled?: boolean;
  id?: string;
  name?: string;
  updated_at?: string;
}

export interface SessionResponse {
  aal?: string;
  created_at?: string;
  id?: string;
  ip?: string;
  refreshed_at?: string;
  updated_at?: string;
  user_agent?: string;
  user_id?: string;
}

export interface SessionStatsResponse {
  active_sessions?: number;
  expired_sessions?: number;
  total_sessions?: number;
}

export interface StatsResponse {
  count?: number;
}

export interface UpdateInstanceConfigRequest {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfig;
}

export interface UpdateInstanceConfigResponse {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfig;
  message?: string;
}

export interface UpdateSAMLProviderRequest {
  enabled?: boolean;
  name?: string;
}

export interface UserIdentity {
  created_at?: string;
  id?: string;
  identity_data?: Record<string, any>;
  identity_id?: string;
  last_sign_in_at?: string;
  provider?: string;
  updated_at?: string;
  user_id?: string;
}
