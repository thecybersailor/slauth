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
   * URLs that auth providers are permitted to redirect to post authentication. Wildcards are allowed, for example, https://*.domain.com
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
   * Access token TTL
   * The time-to-live (TTL) for access tokens. Recommendation: 1 hour.
   */
  accessTokenTTL?: TimeDuration;
  /**
   * Enforce single session per user
   * If enabled, all but a user's most recently active session will be terminated.
   */
  enforceSingleSessionPerUser?: boolean;
  /**
   * Inactivity timeout
   * The amount of time a user needs to be inactive to be forced to sign in again. Use 0 for never.
   */
  inactivityTimeout?: TimeDuration;
  /**
   * Refresh token reuse interval
   * Time interval where the same refresh token can be used multiple times
   * to request for an access token. Recommendation: 10 seconds.
   */
  refreshTokenReuseInterval?: TimeDuration;
  /**
   * Refresh token TTL
   * The time-to-live (TTL) for refresh tokens. Recommendation: 1 week.
   */
  refreshTokenTTL?: TimeDuration;
  /**
   * Detect and revoke potentially compromised refresh tokens
   * Prevent replay attacks from potentially compromised refresh tokens.
   */
  revokeCompromisedRefreshTokens?: boolean;
  /**
   * Time-box user sessions
   * The amount of time before a user is forced to sign in again. Use 0 for never.
   */
  timeBoxUserSessions?: TimeDuration;
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
  app_metadata?: Record<string, any>;
  banned_until?: string;
  created_at?: string;
  email?: string;
  email_confirmed?: boolean;
  id?: string;
  is_anonymous?: boolean;
  last_sign_in_at?: string;
  phone?: string;
  phone_confirmed?: boolean;
  updated_at?: string;
  user_metadata?: Record<string, any>;
}

export interface CreateSAMLProviderRequest {
  enabled?: boolean;
  name: string;
}

export interface GetInstanceConfigResponse {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfig;
  domain_code?: string;
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
