/* eslint-disable */
/* tslint:disable */
/*
 * ---------------------------------------------------------------
 * ## THIS FILE WAS GENERATED VIA SWAGGER-TYPESCRIPT-API        ##
 * ##                                                           ##
 * ## AUTHOR: acacode                                           ##
 * ## SOURCE: https://github.com/acacode/swagger-typescript-api ##
 * ---------------------------------------------------------------
 */

export interface GithubComThecybersailorSlauthPkgConfigAALPolicy {
  aal_timeout?: TimeDuration;
  allow_downgrade?: boolean;
}

export interface GithubComThecybersailorSlauthPkgConfigAALPolicyPatch {
  aal_timeout?: TimeDuration;
  allow_downgrade?: boolean;
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
  mfa_update_required_aal?: GithubComThecybersailorSlauthPkgTypesAALLevel;
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

export interface GithubComThecybersailorSlauthPkgConfigAuthServiceConfigPatch {
  allow_new_users?: boolean;
  anonymous_sign_ins?: boolean;
  auth_service_base_url?: string;
  confirm_email?: boolean;
  enable_captcha?: boolean;
  manual_linking?: boolean;
  max_time_allowed_for_auth_request?: TimeDuration;
  maximum_mfa_factor_validation_attempts?: number;
  maximum_mfa_factors?: number;
  mfa_update_required_aal?: GithubComThecybersailorSlauthPkgTypesAALLevel;
  ratelimit_config?: GithubComThecybersailorSlauthPkgConfigRatelimitConfigPatch;
  redirect_urls?: string[];
  security_config?: GithubComThecybersailorSlauthPkgConfigSecurityConfigPatch;
  session_config?: GithubComThecybersailorSlauthPkgConfigSessionConfigPatch;
  site_url?: string;
}

export interface GithubComThecybersailorSlauthPkgConfigIdentityChangeConfig {
  rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  require_current_value_confirmation?: boolean;
  required_aal?: GithubComThecybersailorSlauthPkgTypesAALLevel;
}

export interface GithubComThecybersailorSlauthPkgConfigIdentityChangeConfigPatch {
  rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  require_current_value_confirmation?: boolean;
  required_aal?: GithubComThecybersailorSlauthPkgTypesAALLevel;
}

export interface GithubComThecybersailorSlauthPkgConfigPasswordStrengthConfig {
  min_score?: number;
}

export interface GithubComThecybersailorSlauthPkgConfigPasswordStrengthConfigPatch {
  min_score?: number;
}

export interface GithubComThecybersailorSlauthPkgConfigPasswordUpdateConfig {
  rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimit;
  revoke_other_sessions?: boolean;
  update_required_aal?: GithubComThecybersailorSlauthPkgTypesAALLevel;
}

export interface GithubComThecybersailorSlauthPkgConfigPasswordUpdateConfigPatch {
  rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  revoke_other_sessions?: boolean;
  update_required_aal?: GithubComThecybersailorSlauthPkgTypesAALLevel;
}

export interface GithubComThecybersailorSlauthPkgConfigRateLimit {
  /** Description provides context about what this rate limit applies to */
  description?: string;
  /** MaxRequests is the maximum number of requests allowed */
  max_requests?: number;
  /** WindowDuration is the time window for the rate limit */
  window_duration?: TimeDuration;
}

export interface GithubComThecybersailorSlauthPkgConfigRateLimitPatch {
  description?: string;
  max_requests?: number;
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

export interface GithubComThecybersailorSlauthPkgConfigRatelimitConfigPatch {
  anonymous_users_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  email_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  sign_up_sign_in_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  sms_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  token_refresh_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  token_verification_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
  web3_sign_up_sign_in_rate_limit?: GithubComThecybersailorSlauthPkgConfigRateLimitPatch;
}

export interface GithubComThecybersailorSlauthPkgConfigSecurityConfig {
  aal_policy?: GithubComThecybersailorSlauthPkgConfigAALPolicy;
  email_change_config?: GithubComThecybersailorSlauthPkgConfigIdentityChangeConfig;
  password_strength_config?: GithubComThecybersailorSlauthPkgConfigPasswordStrengthConfig;
  password_update_config?: GithubComThecybersailorSlauthPkgConfigPasswordUpdateConfig;
  phone_change_config?: GithubComThecybersailorSlauthPkgConfigIdentityChangeConfig;
}

export interface GithubComThecybersailorSlauthPkgConfigSecurityConfigPatch {
  aal_policy?: GithubComThecybersailorSlauthPkgConfigAALPolicyPatch;
  email_change_config?: GithubComThecybersailorSlauthPkgConfigIdentityChangeConfigPatch;
  password_strength_config?: GithubComThecybersailorSlauthPkgConfigPasswordStrengthConfigPatch;
  password_update_config?: GithubComThecybersailorSlauthPkgConfigPasswordUpdateConfigPatch;
  phone_change_config?: GithubComThecybersailorSlauthPkgConfigIdentityChangeConfigPatch;
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

export interface GithubComThecybersailorSlauthPkgConfigSessionConfigPatch {
  access_token_ttl?: number;
  enforce_single_session_per_user?: boolean;
  inactivity_timeout?: number;
  refresh_token_reuse_interval?: number;
  refresh_token_ttl?: number;
  revoke_compromised_refresh_tokens?: boolean;
  time_box_user_sessions?: number;
}

export enum GithubComThecybersailorSlauthPkgTypesAALLevel {
  AALLevel1 = "aal1",
  AALLevel2 = "aal2",
  AALLevel3 = "aal3",
}

export enum GithubComThecybersailorSlauthPkgTypesFactorStatus {
  FactorStatusUnverified = "unverified",
  FactorStatusVerified = "verified",
}

export enum GithubComThecybersailorSlauthPkgTypesFactorType {
  FactorTypeTOTP = "totp",
  FactorTypeWebAuthn = "webauthn",
  FactorTypePhone = "phone",
}

export interface PkgControllerAdminCreateUserRequest {
  app_metadata?: Record<string, any>;
  email?: string;
  email_confirmed?: boolean;
  password?: string;
  phone?: string;
  phone_confirmed?: boolean;
  user_data?: Record<string, any>;
  user_metadata?: Record<string, any>;
}

export interface PkgControllerAdminResetPasswordRequest {
  new_password?: string;
}

export interface PkgControllerAdminUpdateUserRequest {
  app_metadata?: Record<string, any>;
  banned_until?: string;
  email?: string;
  email_confirmed?: boolean;
  phone?: string;
  phone_confirmed?: boolean;
  user_data?: Record<string, any>;
}

export interface PkgControllerAdminUserResponse {
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
  factors?: PkgControllerFactor[];
  /** @example "user_123" */
  id?: string;
  identities?: PkgControllerUserIdentity[];
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

export interface PkgControllerCreateSAMLProviderRequest {
  enabled?: boolean;
  name: string;
}

export interface PkgControllerFactor {
  created_at?: string;
  friendly_name?: string;
  id?: string;
  status?: GithubComThecybersailorSlauthPkgTypesFactorStatus;
  type?: GithubComThecybersailorSlauthPkgTypesFactorType;
  updated_at?: string;
}

export interface PkgControllerGetInstanceConfigResponse {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfig;
  instance_id?: string;
}

export interface PkgControllerListSAMLProvidersResponse {
  page?: number;
  page_size?: number;
  providers?: PkgControllerSAMLProviderResponse[];
  total?: number;
}

export interface PkgControllerListSessionsResponse {
  page?: number;
  page_size?: number;
  sessions?: PkgControllerSessionResponse[];
  total?: number;
}

export interface PkgControllerListUsersResponse {
  page?: number;
  page_size?: number;
  total?: number;
  users?: PkgControllerAdminUserResponse[];
}

export interface PkgControllerQueryPagination {
  page?: number;
  pageSize?: number;
}

export interface PkgControllerQueryUsersRequest {
  filters?: Record<string, any>;
  pagination?: PkgControllerQueryPagination;
  sort?: string[];
}

export interface PkgControllerSAMLProviderResponse {
  created_at?: string;
  enabled?: boolean;
  id?: string;
  name?: string;
  updated_at?: string;
}

export interface PkgControllerSessionResponse {
  aal?: string;
  created_at?: string;
  id?: string;
  ip?: string;
  refreshed_at?: string;
  updated_at?: string;
  user_agent?: string;
  user_id?: string;
}

export interface PkgControllerSessionStatsResponse {
  active_sessions?: number;
  expired_sessions?: number;
  total_sessions?: number;
}

export interface PkgControllerStatsResponse {
  count?: number;
}

export interface PkgControllerUpdateInstanceConfigRequest {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfigPatch;
}

export interface PkgControllerUpdateInstanceConfigResponse {
  config?: GithubComThecybersailorSlauthPkgConfigAuthServiceConfig;
  message?: string;
}

export interface PkgControllerUpdateSAMLProviderRequest {
  enabled?: boolean;
  name?: string;
}

export interface PkgControllerUserIdentity {
  created_at?: string;
  id?: string;
  identity_data?: Record<string, any>;
  identity_id?: string;
  last_sign_in_at?: string;
  provider?: string;
  updated_at?: string;
  user_id?: string;
}

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

export type QueryParamsType = Record<string | number, any>;
export type ResponseFormat = keyof Omit<Body, "body" | "bodyUsed">;

export interface FullRequestParams extends Omit<RequestInit, "body"> {
  /** set parameter to `true` for call `securityWorker` for this request */
  secure?: boolean;
  /** request path */
  path: string;
  /** content type of request body */
  type?: ContentType;
  /** query params */
  query?: QueryParamsType;
  /** format of response (i.e. response.json() -> format: "json") */
  format?: ResponseFormat;
  /** request body */
  body?: unknown;
  /** base url */
  baseUrl?: string;
  /** request cancellation token */
  cancelToken?: CancelToken;
}

export type RequestParams = Omit<FullRequestParams, "body" | "method" | "query" | "path">;

export interface ApiConfig<SecurityDataType = unknown> {
  baseUrl?: string;
  baseApiParams?: Omit<RequestParams, "baseUrl" | "cancelToken" | "signal">;
  securityWorker?: (securityData: SecurityDataType | null) => Promise<RequestParams | void> | RequestParams | void;
  customFetch?: typeof fetch;
}

export interface HttpResponse<D extends unknown, E extends unknown = unknown> extends Response {
  data: D;
  error: E;
}

type CancelToken = Symbol | string | number;

export enum ContentType {
  Json = "application/json",
  FormData = "multipart/form-data",
  UrlEncoded = "application/x-www-form-urlencoded",
  Text = "text/plain",
}

export class HttpClient<SecurityDataType = unknown> {
  public baseUrl: string = "//localhost:8080";
  private securityData: SecurityDataType | null = null;
  private securityWorker?: ApiConfig<SecurityDataType>["securityWorker"];
  private abortControllers = new Map<CancelToken, AbortController>();
  private customFetch = (...fetchParams: Parameters<typeof fetch>) => fetch(...fetchParams);

  private baseApiParams: RequestParams = {
    credentials: "same-origin",
    headers: {},
    redirect: "follow",
    referrerPolicy: "no-referrer",
  };

  constructor(apiConfig: ApiConfig<SecurityDataType> = {}) {
    Object.assign(this, apiConfig);
  }

  public setSecurityData = (data: SecurityDataType | null) => {
    this.securityData = data;
  };

  protected encodeQueryParam(key: string, value: any) {
    const encodedKey = encodeURIComponent(key);
    return `${encodedKey}=${encodeURIComponent(typeof value === "number" ? value : `${value}`)}`;
  }

  protected addQueryParam(query: QueryParamsType, key: string) {
    return this.encodeQueryParam(key, query[key]);
  }

  protected addArrayQueryParam(query: QueryParamsType, key: string) {
    const value = query[key];
    return value.map((v: any) => this.encodeQueryParam(key, v)).join("&");
  }

  protected toQueryString(rawQuery?: QueryParamsType): string {
    const query = rawQuery || {};
    const keys = Object.keys(query).filter((key) => "undefined" !== typeof query[key]);
    return keys
      .map((key) => (Array.isArray(query[key]) ? this.addArrayQueryParam(query, key) : this.addQueryParam(query, key)))
      .join("&");
  }

  protected addQueryParams(rawQuery?: QueryParamsType): string {
    const queryString = this.toQueryString(rawQuery);
    return queryString ? `?${queryString}` : "";
  }

  private contentFormatters: Record<ContentType, (input: any) => any> = {
    [ContentType.Json]: (input: any) =>
      input !== null && (typeof input === "object" || typeof input === "string") ? JSON.stringify(input) : input,
    [ContentType.Text]: (input: any) => (input !== null && typeof input !== "string" ? JSON.stringify(input) : input),
    [ContentType.FormData]: (input: any) =>
      Object.keys(input || {}).reduce((formData, key) => {
        const property = input[key];
        formData.append(
          key,
          property instanceof Blob
            ? property
            : typeof property === "object" && property !== null
              ? JSON.stringify(property)
              : `${property}`,
        );
        return formData;
      }, new FormData()),
    [ContentType.UrlEncoded]: (input: any) => this.toQueryString(input),
  };

  protected mergeRequestParams(params1: RequestParams, params2?: RequestParams): RequestParams {
    return {
      ...this.baseApiParams,
      ...params1,
      ...(params2 || {}),
      headers: {
        ...(this.baseApiParams.headers || {}),
        ...(params1.headers || {}),
        ...((params2 && params2.headers) || {}),
      },
    };
  }

  protected createAbortSignal = (cancelToken: CancelToken): AbortSignal | undefined => {
    if (this.abortControllers.has(cancelToken)) {
      const abortController = this.abortControllers.get(cancelToken);
      if (abortController) {
        return abortController.signal;
      }
      return void 0;
    }

    const abortController = new AbortController();
    this.abortControllers.set(cancelToken, abortController);
    return abortController.signal;
  };

  public abortRequest = (cancelToken: CancelToken) => {
    const abortController = this.abortControllers.get(cancelToken);

    if (abortController) {
      abortController.abort();
      this.abortControllers.delete(cancelToken);
    }
  };

  public request = async <T = any, E = any>({
    body,
    secure,
    path,
    type,
    query,
    format,
    baseUrl,
    cancelToken,
    ...params
  }: FullRequestParams): Promise<HttpResponse<T, E>> => {
    const secureParams =
      ((typeof secure === "boolean" ? secure : this.baseApiParams.secure) &&
        this.securityWorker &&
        (await this.securityWorker(this.securityData))) ||
      {};
    const requestParams = this.mergeRequestParams(params, secureParams);
    const queryString = query && this.toQueryString(query);
    const payloadFormatter = this.contentFormatters[type || ContentType.Json];
    const responseFormat = format || requestParams.format;

    return this.customFetch(`${baseUrl || this.baseUrl || ""}${path}${queryString ? `?${queryString}` : ""}`, {
      ...requestParams,
      headers: {
        ...(requestParams.headers || {}),
        ...(type && type !== ContentType.FormData ? { "Content-Type": type } : {}),
      },
      signal: (cancelToken ? this.createAbortSignal(cancelToken) : requestParams.signal) || null,
      body: typeof body === "undefined" || body === null ? null : payloadFormatter(body),
    }).then(async (response) => {
      const r = response.clone() as HttpResponse<T, E>;
      r.data = null as unknown as T;
      r.error = null as unknown as E;

      const data = !responseFormat
        ? r
        : await response[responseFormat]()
            .then((data) => {
              if (r.ok) {
                r.data = data;
              } else {
                r.error = data;
              }
              return r;
            })
            .catch((e) => {
              r.error = e;
              return r;
            });

      if (cancelToken) {
        this.abortControllers.delete(cancelToken);
      }

      if (!response.ok) throw data;
      return data;
    });
  };
}

/**
 * @title slauth Platform API
 * @version 1.0
 * @license MIT (https://opensource.org/licenses/MIT)
 * @termsOfService https://aira.com/terms
 * @baseUrl //localhost:8080
 * @contact Aira API Support <support@aira.com>
 *
 * Complete authentication and administrative management API for Aira platform
 */
export class Api<SecurityDataType extends unknown> extends HttpClient<SecurityDataType> {
  config = {
    /**
     * @description Get configuration for the current instance instance
     *
     * @tags Admin
     * @name ConfigList
     * @summary Get Instance Config
     * @request GET:/config
     * @secure
     */
    configList: (params: RequestParams = {}) =>
      this.request<PkgControllerGetInstanceConfigResponse, any>({
        path: `/config`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Update configuration for the current instance instance
     *
     * @tags Admin
     * @name ConfigUpdate
     * @summary Update Instance Config
     * @request PUT:/config
     * @secure
     */
    configUpdate: (request: PkgControllerUpdateInstanceConfigRequest, params: RequestParams = {}) =>
      this.request<PkgControllerUpdateInstanceConfigResponse, any>({
        path: `/config`,
        method: "PUT",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),
  };
  saml = {
    /**
     * @description Get list of SAML SSO providers (admin only)
     *
     * @tags Admin
     * @name ProvidersList
     * @summary List SAML Providers
     * @request GET:/saml/providers
     * @secure
     */
    providersList: (
      query?: {
        /**
         * Page number
         * @default 1
         */
        page?: number;
        /**
         * Page size
         * @default 20
         */
        page_size?: number;
      },
      params: RequestParams = {},
    ) =>
      this.request<PkgControllerListSAMLProvidersResponse, any>({
        path: `/saml/providers`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Create a new SAML SSO provider (admin only)
     *
     * @tags Admin
     * @name ProvidersCreate
     * @summary Create SAML Provider
     * @request POST:/saml/providers
     * @secure
     */
    providersCreate: (request: PkgControllerCreateSAMLProviderRequest, params: RequestParams = {}) =>
      this.request<PkgControllerSAMLProviderResponse, any>({
        path: `/saml/providers`,
        method: "POST",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Get SAML provider details (admin only)
     *
     * @tags Admin
     * @name ProvidersDetail
     * @summary Get SAML Provider
     * @request GET:/saml/providers/{id}
     * @secure
     */
    providersDetail: (id: string, params: RequestParams = {}) =>
      this.request<PkgControllerSAMLProviderResponse, any>({
        path: `/saml/providers/${id}`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Update SAML provider configuration (admin only)
     *
     * @tags Admin
     * @name ProvidersUpdate
     * @summary Update SAML Provider
     * @request PUT:/saml/providers/{id}
     * @secure
     */
    providersUpdate: (id: string, request: PkgControllerUpdateSAMLProviderRequest, params: RequestParams = {}) =>
      this.request<PkgControllerSAMLProviderResponse, any>({
        path: `/saml/providers/${id}`,
        method: "PUT",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Delete SAML provider (admin only)
     *
     * @tags Admin
     * @name ProvidersDelete
     * @summary Delete SAML Provider
     * @request DELETE:/saml/providers/{id}
     * @secure
     */
    providersDelete: (id: string, params: RequestParams = {}) =>
      this.request<Record<string, string>, any>({
        path: `/saml/providers/${id}`,
        method: "DELETE",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Test SAML provider configuration (admin only)
     *
     * @tags Admin
     * @name ProvidersTestCreate
     * @summary Test SAML Provider
     * @request POST:/saml/providers/{id}/test
     * @secure
     */
    providersTestCreate: (id: string, params: RequestParams = {}) =>
      this.request<Record<string, any>, any>({
        path: `/saml/providers/${id}/test`,
        method: "POST",
        secure: true,
        format: "json",
        ...params,
      }),
  };
  sessions = {
    /**
     * @description List all user sessions (admin only)
     *
     * @tags Admin
     * @name SessionsList
     * @summary List All Sessions
     * @request GET:/sessions
     * @secure
     */
    sessionsList: (
      query?: {
        /**
         * Page number
         * @default 1
         */
        page?: number;
        /**
         * Page size
         * @default 20
         */
        page_size?: number;
      },
      params: RequestParams = {},
    ) =>
      this.request<PkgControllerListSessionsResponse, any>({
        path: `/sessions`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Revoke a specific user session (admin only)
     *
     * @tags Admin
     * @name SessionsDelete
     * @summary Revoke User Session
     * @request DELETE:/sessions/{id}
     * @secure
     */
    sessionsDelete: (id: string, params: RequestParams = {}) =>
      this.request<Record<string, string>, any>({
        path: `/sessions/${id}`,
        method: "DELETE",
        secure: true,
        format: "json",
        ...params,
      }),
  };
  stats = {
    /**
     * @description Get recent user signins statistics (admin only)
     *
     * @tags Admin
     * @name RecentSigninsList
     * @summary Get Recent Signins
     * @request GET:/stats/recent-signins
     * @secure
     */
    recentSigninsList: (
      query?: {
        /**
         * Maximum number of signins to include
         * @default 50
         */
        limit?: number;
      },
      params: RequestParams = {},
    ) =>
      this.request<Record<string, any>, any>({
        path: `/stats/recent-signins`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Get recent user signups statistics (admin only)
     *
     * @tags Admin
     * @name RecentSignupsList
     * @summary Get Recent Signups
     * @request GET:/stats/recent-signups
     * @secure
     */
    recentSignupsList: (
      query?: {
        /**
         * Number of days to include
         * @default 7
         */
        days?: number;
      },
      params: RequestParams = {},
    ) =>
      this.request<Record<string, any>, any>({
        path: `/stats/recent-signups`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Get active session count (admin only)
     *
     * @tags Admin
     * @name SessionsList
     * @summary Get Active Session Count
     * @request GET:/stats/sessions
     * @secure
     */
    sessionsList: (params: RequestParams = {}) =>
      this.request<PkgControllerSessionStatsResponse, any>({
        path: `/stats/sessions`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Get total user count (admin only)
     *
     * @tags Admin
     * @name UsersList
     * @summary Get User Count
     * @request GET:/stats/users
     * @secure
     */
    usersList: (params: RequestParams = {}) =>
      this.request<PkgControllerStatsResponse, any>({
        path: `/stats/users`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),
  };
  users = {
    /**
     * @description Create a new user account (admin only)
     *
     * @tags Admin
     * @name UsersCreate
     * @summary Create New User
     * @request POST:/users
     * @secure
     */
    usersCreate: (request: PkgControllerAdminCreateUserRequest, params: RequestParams = {}) =>
      this.request<PkgControllerAdminUserResponse, any>({
        path: `/users`,
        method: "POST",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Query users with complex filters using Strapi-style syntax
     *
     * @tags Admin
     * @name QueryCreate
     * @summary Query Users (Strapi-style)
     * @request POST:/users/query
     * @secure
     */
    queryCreate: (request: PkgControllerQueryUsersRequest, params: RequestParams = {}) =>
      this.request<PkgControllerListUsersResponse, any>({
        path: `/users/query`,
        method: "POST",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Get detailed user information by user ID
     *
     * @tags Admin
     * @name UsersDetail
     * @summary Get User by ID
     * @request GET:/users/{id}
     * @secure
     */
    usersDetail: (id: string, params: RequestParams = {}) =>
      this.request<PkgControllerAdminUserResponse, any>({
        path: `/users/${id}`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Update user information (admin only)
     *
     * @tags Admin
     * @name UsersUpdate
     * @summary Update User
     * @request PUT:/users/{id}
     * @secure
     */
    usersUpdate: (id: string, request: PkgControllerAdminUpdateUserRequest, params: RequestParams = {}) =>
      this.request<PkgControllerAdminUserResponse, any>({
        path: `/users/${id}`,
        method: "PUT",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Delete user account (admin only)
     *
     * @tags Admin
     * @name UsersDelete
     * @summary Delete User
     * @request DELETE:/users/{id}
     * @secure
     */
    usersDelete: (id: string, params: RequestParams = {}) =>
      this.request<Record<string, string>, any>({
        path: `/users/${id}`,
        method: "DELETE",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Set user email confirmation status (admin only)
     *
     * @tags Admin
     * @name EmailConfirmedUpdate
     * @summary Set User Email Confirmed Status
     * @request PUT:/users/{id}/email-confirmed
     * @secure
     */
    emailConfirmedUpdate: (
      id: string,
      request: {
        confirmed?: boolean;
      },
      params: RequestParams = {},
    ) =>
      this.request<Record<string, string>, any>({
        path: `/users/${id}/email-confirmed`,
        method: "PUT",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description List user identities (admin only)
     *
     * @tags Admin
     * @name IdentitiesDetail
     * @summary List User Identities
     * @request GET:/users/{id}/identities
     * @secure
     */
    identitiesDetail: (id: string, params: RequestParams = {}) =>
      this.request<Record<string, any>, any>({
        path: `/users/${id}/identities`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Delete user identity (admin only)
     *
     * @tags Admin
     * @name IdentitiesDelete
     * @summary Delete User Identity
     * @request DELETE:/users/{id}/identities/{identity_id}
     * @secure
     */
    identitiesDelete: (id: string, identityId: string, params: RequestParams = {}) =>
      this.request<Record<string, string>, any>({
        path: `/users/${id}/identities/${identityId}`,
        method: "DELETE",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Set user phone confirmation status (admin only)
     *
     * @tags Admin
     * @name PhoneConfirmedUpdate
     * @summary Set User Phone Confirmed Status
     * @request PUT:/users/{id}/phone-confirmed
     * @secure
     */
    phoneConfirmedUpdate: (
      id: string,
      request: {
        confirmed?: boolean;
      },
      params: RequestParams = {},
    ) =>
      this.request<Record<string, string>, any>({
        path: `/users/${id}/phone-confirmed`,
        method: "PUT",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Reset user password (admin only)
     *
     * @tags Admin
     * @name ResetPasswordCreate
     * @summary Reset User Password
     * @request POST:/users/{id}/reset-password
     * @secure
     */
    resetPasswordCreate: (id: string, request: PkgControllerAdminResetPasswordRequest, params: RequestParams = {}) =>
      this.request<Record<string, string>, any>({
        path: `/users/${id}/reset-password`,
        method: "POST",
        body: request,
        secure: true,
        type: ContentType.Json,
        format: "json",
        ...params,
      }),

    /**
     * @description Get list of user sessions (admin only)
     *
     * @tags Admin
     * @name SessionsDetail
     * @summary List User Sessions
     * @request GET:/users/{id}/sessions
     * @secure
     */
    sessionsDetail: (
      id: string,
      query?: {
        /**
         * Page number
         * @default 1
         */
        page?: number;
        /**
         * Page size
         * @default 20
         */
        page_size?: number;
      },
      params: RequestParams = {},
    ) =>
      this.request<PkgControllerListSessionsResponse, any>({
        path: `/users/${id}/sessions`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * @description Revoke all sessions for a specific user (admin only)
     *
     * @tags Admin
     * @name SessionsDelete
     * @summary Revoke All User Sessions
     * @request DELETE:/users/{id}/sessions
     * @secure
     */
    sessionsDelete: (id: string, params: RequestParams = {}) =>
      this.request<Record<string, string>, any>({
        path: `/users/${id}/sessions`,
        method: "DELETE",
        secure: true,
        format: "json",
        ...params,
      }),
  };
}
