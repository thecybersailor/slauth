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

export enum FactorType {
  FactorTypeTOTP = "totp",
  FactorTypeWebAuthn = "webauthn",
  FactorTypePhone = "phone",
}

export enum FactorStatus {
  FactorStatusUnverified = "unverified",
  FactorStatusVerified = "verified",
}

export interface ResetPasswordOptions {
  captchaToken?: string;
  redirect_to?: string;
}

export interface SignInWithOtpOptions {
  captchaToken?: string;
  /** sms, whatsapp */
  channel?: string;
  data?: Record<string, any>;
  emailRedirectTo?: string;
  redirect_to?: string;
  shouldCreateUser?: boolean;
}

export interface SignInWithPasswordOptions {
  captchaToken?: string;
  redirect_to?: string;
}

export interface SignUpOptions {
  captchaToken?: string;
  /** sms, whatsapp */
  channel?: string;
  /** Additional data like is_anonymous */
  data?: Record<string, any>;
  emailRedirectTo?: string;
  redirect_to?: string;
}

export interface VerifyOtpOptions {
  captchaToken?: string;
  redirect_to?: string;
}

/** Authentication response containing user and session information */
export interface AuthData {
  redirect_to?: string;
  /** Authentication session with tokens */
  session?: Session;
  /** User account information */
  user?: User;
  weakPassword?: WeakPassword;
}

/** OAuth authorization code exchange request (PKCE flow) */
export interface ExchangeCodeRequest {
  /** @example "abc123def456" */
  auth_code?: string;
  /** @example "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" */
  code_verifier?: string;
  /** @example "flow_123" */
  flow_id?: string;
  /** @example "random_state_string" */
  state?: string;
}

export interface Factor {
  created_at?: string;
  friendly_name?: string;
  id?: string;
  status?: FactorStatus;
  type?: FactorType;
  updated_at?: string;
}

export interface GetAuditLogResponse {
  events?: Record<string, any>[];
}

export interface GetDevicesResponse {
  devices?: Record<string, any>[];
}

export interface ListSessionsResponse {
  page?: number;
  page_size?: number;
  sessions?: SessionResponse[];
  total?: number;
}

export interface MFAChallengeData {
  expires_at?: number;
  id?: string;
  type?: FactorType;
}

/** Response data for MFA factor enrollment */
export interface MFAEnrollData {
  /** @example "My Phone" */
  friendly_name?: string;
  /** @example "factor_123" */
  id?: string;
  /** @example "+1234567890" */
  phone?: string;
  totp?: TOTPEnrollData;
  /** @example "totp" */
  type?: FactorType;
}

/** Request to enroll a new MFA factor */
export interface MFAEnrollRequest {
  /** @example "totp" */
  factorType?: FactorType;
  /** @example "My Phone" */
  friendlyName?: string;
  /** @example "MyApp" */
  issuer?: string;
  /** @example "+1234567890" */
  phone?: string;
}

export interface MFAListFactorsData {
  all?: Factor[];
  phone?: Factor[];
  totp?: Factor[];
}

export interface MFAUnenrollData {
  id?: string;
}

export interface MFAVerifyData {
  access_token?: string;
  expires_in?: number;
  refresh_token?: string;
  token_type?: string;
  /** User account information */
  user?: User;
}

/** Request to verify MFA challenge */
export interface MFAVerifyRequest {
  /** @example "challenge_456" */
  challengeId?: string;
  /** @example "123456" */
  code?: string;
  /** @example "factor_123" */
  factorId?: string;
}

export interface OAuthData {
  config?: any;
  flow_id?: string;
  provider?: string;
}

/** Refresh token request */
export interface RefreshTokenRequest {
  /** @example "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." */
  refresh_token?: string;
}

export interface ResendOptions {
  captchaToken?: string;
  emailRedirectTo?: string;
}

export interface ResendRequest {
  email?: string;
  options?: ResendOptions;
  phone?: string;
  /** signup, email_change, sms, phone_change */
  type?: string;
}

export interface ResetPasswordRequest {
  email?: string;
  options?: ResetPasswordOptions;
  phone?: string;
}

export interface SSOData {
  url?: string;
}

export interface SendOTPRequest {
  /** sms, whatsapp */
  channel?: string;
  email?: string;
  phone?: string;
}

export interface SendOTPResponse {
  messageId?: string;
}

export interface SendSMSOTPRequest {
  /** sms, whatsapp */
  channel?: string;
  phone?: string;
}

export interface SendSMSOTPResponse {
  messageId?: string;
}

/** Authentication session with tokens */
export interface Session {
  /** @example "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." */
  access_token?: string;
  /** @example 1672531200 */
  expires_at?: number;
  /** @example 3600 */
  expires_in?: number;
  /** @example "session_123" */
  id?: string;
  provider_refresh_token?: string;
  provider_token?: string;
  /** @example "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." */
  refresh_token?: string;
  /** @example "Bearer" */
  token_type?: string;
  /** User account information */
  user?: User;
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

export interface SignInWithIdTokenRequest {
  credential?: Record<string, string>;
  /** @example "google" */
  provider?: string;
}

/** OAuth authentication request */
export interface SignInWithOAuthRequest {
  options?: Record<string, string>;
  /** @example "google" */
  provider?: string;
  redirect_to?: string;
}

export interface SignInWithOtpRequest {
  email?: string;
  options?: SignInWithOtpOptions;
  phone?: string;
}

export interface SignInWithPasswordRequest {
  email?: string;
  options?: SignInWithPasswordOptions;
  password?: string;
  phone?: string;
}

export interface SignInWithSSOOptions {
  captchaToken?: string;
  redirectTo?: string;
}

export interface SignInWithSSORequest {
  instance?: string;
  options?: SignInWithSSOOptions;
  providerId?: string;
}

export interface SignOutRequest {
  /** global, local, others */
  scope?: string;
}

export interface SignUpRequest {
  email?: string;
  options?: SignUpOptions;
  password?: string;
  phone?: string;
  user_metadata?: Record<string, any>;
}

export interface SuccessResponse {
  success?: boolean;
}

export interface TOTPEnrollData {
  qr_code?: string;
  secret?: string;
  uri?: string;
}

export interface UpdatePasswordRequest {
  nonce?: string;
  password?: string;
}

export interface UpdateUserOptions {
  emailRedirectTo?: string;
}

export interface UpdateUserProfileRequest {
  email?: string;
  emailRedirectTo?: string;
  password?: string;
  phone?: string;
  user_metadata?: Record<string, any>;
}

export interface UpdateUserRequest {
  email?: string;
  nonce?: string;
  options?: UpdateUserOptions;
  password?: string;
  phone?: string;
  user_metadata?: Record<string, any>;
}

/** User account information */
export interface User {
  aal?: any;
  app_metadata?: Record<string, any>;
  /** @example "authenticated" */
  aud?: string;
  /** @example "2023-01-01T00:00:00Z" */
  confirmed_at?: string;
  /** @example "2023-01-01T00:00:00Z" */
  created_at?: string;
  /** @example "user@example.com" */
  email?: string;
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
  /** @example "2023-01-01T00:00:00Z" */
  phone_confirmed_at?: string;
  /** @example "user" */
  role?: string;
  /** @example "2023-01-01T00:00:00Z" */
  updated_at?: string;
  user_metadata?: Record<string, any>;
}

export interface UserData {
  /** User account information */
  user?: User;
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

export interface UserResponse {
  /** User account information */
  user?: User;
}

export interface VerifyOtpRequest {
  email?: string;
  options?: VerifyOtpOptions;
  phone?: string;
  token?: string;
  token_hash?: string;
  /** signup, invite, magiclink, recovery, email_change, sms, phone_change */
  type?: string;
}

export interface WeakPassword {
  message?: string;
  reasons?: string[];
}
