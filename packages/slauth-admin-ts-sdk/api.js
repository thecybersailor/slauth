var GithubComThecybersailorSlauthPkgTypesAALLevel = /* @__PURE__ */ ((GithubComThecybersailorSlauthPkgTypesAALLevel2) => {
  GithubComThecybersailorSlauthPkgTypesAALLevel2["AALLevel1"] = "aal1";
  GithubComThecybersailorSlauthPkgTypesAALLevel2["AALLevel2"] = "aal2";
  GithubComThecybersailorSlauthPkgTypesAALLevel2["AALLevel3"] = "aal3";
  return GithubComThecybersailorSlauthPkgTypesAALLevel2;
})(GithubComThecybersailorSlauthPkgTypesAALLevel || {});
var GithubComThecybersailorSlauthPkgTypesFactorStatus = /* @__PURE__ */ ((GithubComThecybersailorSlauthPkgTypesFactorStatus2) => {
  GithubComThecybersailorSlauthPkgTypesFactorStatus2["FactorStatusUnverified"] = "unverified";
  GithubComThecybersailorSlauthPkgTypesFactorStatus2["FactorStatusVerified"] = "verified";
  return GithubComThecybersailorSlauthPkgTypesFactorStatus2;
})(GithubComThecybersailorSlauthPkgTypesFactorStatus || {});
var GithubComThecybersailorSlauthPkgTypesFactorType = /* @__PURE__ */ ((GithubComThecybersailorSlauthPkgTypesFactorType2) => {
  GithubComThecybersailorSlauthPkgTypesFactorType2["FactorTypeTOTP"] = "totp";
  GithubComThecybersailorSlauthPkgTypesFactorType2["FactorTypeWebAuthn"] = "webauthn";
  GithubComThecybersailorSlauthPkgTypesFactorType2["FactorTypePhone"] = "phone";
  return GithubComThecybersailorSlauthPkgTypesFactorType2;
})(GithubComThecybersailorSlauthPkgTypesFactorType || {});
var TimeDuration = /* @__PURE__ */ ((TimeDuration2) => {
  TimeDuration2[TimeDuration2["MinDuration"] = -9223372036854776e3] = "MinDuration";
  TimeDuration2[TimeDuration2["MaxDuration"] = 9223372036854776e3] = "MaxDuration";
  TimeDuration2[TimeDuration2["Nanosecond"] = 1] = "Nanosecond";
  TimeDuration2[TimeDuration2["Microsecond"] = 1e3] = "Microsecond";
  TimeDuration2[TimeDuration2["Millisecond"] = 1e6] = "Millisecond";
  TimeDuration2[TimeDuration2["Second"] = 1e9] = "Second";
  TimeDuration2[TimeDuration2["Minute"] = 6e10] = "Minute";
  TimeDuration2[TimeDuration2["Hour"] = 36e11] = "Hour";
  return TimeDuration2;
})(TimeDuration || {});
var ContentType = /* @__PURE__ */ ((ContentType2) => {
  ContentType2["Json"] = "application/json";
  ContentType2["FormData"] = "multipart/form-data";
  ContentType2["UrlEncoded"] = "application/x-www-form-urlencoded";
  ContentType2["Text"] = "text/plain";
  return ContentType2;
})(ContentType || {});
class HttpClient {
  baseUrl = "//localhost:8080";
  securityData = null;
  securityWorker;
  abortControllers = /* @__PURE__ */ new Map();
  customFetch = (...fetchParams) => fetch(...fetchParams);
  baseApiParams = {
    credentials: "same-origin",
    headers: {},
    redirect: "follow",
    referrerPolicy: "no-referrer"
  };
  constructor(apiConfig = {}) {
    Object.assign(this, apiConfig);
  }
  setSecurityData = (data) => {
    this.securityData = data;
  };
  encodeQueryParam(key, value) {
    const encodedKey = encodeURIComponent(key);
    return `${encodedKey}=${encodeURIComponent(typeof value === "number" ? value : `${value}`)}`;
  }
  addQueryParam(query, key) {
    return this.encodeQueryParam(key, query[key]);
  }
  addArrayQueryParam(query, key) {
    const value = query[key];
    return value.map((v) => this.encodeQueryParam(key, v)).join("&");
  }
  toQueryString(rawQuery) {
    const query = rawQuery || {};
    const keys = Object.keys(query).filter((key) => "undefined" !== typeof query[key]);
    return keys.map((key) => Array.isArray(query[key]) ? this.addArrayQueryParam(query, key) : this.addQueryParam(query, key)).join("&");
  }
  addQueryParams(rawQuery) {
    const queryString = this.toQueryString(rawQuery);
    return queryString ? `?${queryString}` : "";
  }
  contentFormatters = {
    ["application/json" /* Json */]: (input) => input !== null && (typeof input === "object" || typeof input === "string") ? JSON.stringify(input) : input,
    ["text/plain" /* Text */]: (input) => input !== null && typeof input !== "string" ? JSON.stringify(input) : input,
    ["multipart/form-data" /* FormData */]: (input) => Object.keys(input || {}).reduce((formData, key) => {
      const property = input[key];
      formData.append(
        key,
        property instanceof Blob ? property : typeof property === "object" && property !== null ? JSON.stringify(property) : `${property}`
      );
      return formData;
    }, new FormData()),
    ["application/x-www-form-urlencoded" /* UrlEncoded */]: (input) => this.toQueryString(input)
  };
  mergeRequestParams(params1, params2) {
    return {
      ...this.baseApiParams,
      ...params1,
      ...params2 || {},
      headers: {
        ...this.baseApiParams.headers || {},
        ...params1.headers || {},
        ...params2 && params2.headers || {}
      }
    };
  }
  createAbortSignal = (cancelToken) => {
    if (this.abortControllers.has(cancelToken)) {
      const abortController2 = this.abortControllers.get(cancelToken);
      if (abortController2) {
        return abortController2.signal;
      }
      return void 0;
    }
    const abortController = new AbortController();
    this.abortControllers.set(cancelToken, abortController);
    return abortController.signal;
  };
  abortRequest = (cancelToken) => {
    const abortController = this.abortControllers.get(cancelToken);
    if (abortController) {
      abortController.abort();
      this.abortControllers.delete(cancelToken);
    }
  };
  request = async ({
    body,
    secure,
    path,
    type,
    query,
    format,
    baseUrl,
    cancelToken,
    ...params
  }) => {
    const secureParams = (typeof secure === "boolean" ? secure : this.baseApiParams.secure) && this.securityWorker && await this.securityWorker(this.securityData) || {};
    const requestParams = this.mergeRequestParams(params, secureParams);
    const queryString = query && this.toQueryString(query);
    const payloadFormatter = this.contentFormatters[type || "application/json" /* Json */];
    const responseFormat = format || requestParams.format;
    return this.customFetch(`${baseUrl || this.baseUrl || ""}${path}${queryString ? `?${queryString}` : ""}`, {
      ...requestParams,
      headers: {
        ...requestParams.headers || {},
        ...type && type !== "multipart/form-data" /* FormData */ ? { "Content-Type": type } : {}
      },
      signal: (cancelToken ? this.createAbortSignal(cancelToken) : requestParams.signal) || null,
      body: typeof body === "undefined" || body === null ? null : payloadFormatter(body)
    }).then(async (response) => {
      const r = response.clone();
      r.data = null;
      r.error = null;
      const data = !responseFormat ? r : await response[responseFormat]().then((data2) => {
        if (r.ok) {
          r.data = data2;
        } else {
          r.error = data2;
        }
        return r;
      }).catch((e) => {
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
class Api extends HttpClient {
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
    configList: (params = {}) => this.request({
      path: `/config`,
      method: "GET",
      secure: true,
      format: "json",
      ...params
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
    configUpdate: (request, params = {}) => this.request({
      path: `/config`,
      method: "PUT",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
    })
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
    providersList: (query, params = {}) => this.request({
      path: `/saml/providers`,
      method: "GET",
      query,
      secure: true,
      format: "json",
      ...params
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
    providersCreate: (request, params = {}) => this.request({
      path: `/saml/providers`,
      method: "POST",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    providersDetail: (id, params = {}) => this.request({
      path: `/saml/providers/${id}`,
      method: "GET",
      secure: true,
      format: "json",
      ...params
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
    providersUpdate: (id, request, params = {}) => this.request({
      path: `/saml/providers/${id}`,
      method: "PUT",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    providersDelete: (id, params = {}) => this.request({
      path: `/saml/providers/${id}`,
      method: "DELETE",
      secure: true,
      format: "json",
      ...params
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
    providersTestCreate: (id, params = {}) => this.request({
      path: `/saml/providers/${id}/test`,
      method: "POST",
      secure: true,
      format: "json",
      ...params
    })
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
    sessionsList: (query, params = {}) => this.request({
      path: `/sessions`,
      method: "GET",
      query,
      secure: true,
      format: "json",
      ...params
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
    sessionsDelete: (id, params = {}) => this.request({
      path: `/sessions/${id}`,
      method: "DELETE",
      secure: true,
      format: "json",
      ...params
    })
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
    recentSigninsList: (query, params = {}) => this.request({
      path: `/stats/recent-signins`,
      method: "GET",
      query,
      secure: true,
      format: "json",
      ...params
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
    recentSignupsList: (query, params = {}) => this.request({
      path: `/stats/recent-signups`,
      method: "GET",
      query,
      secure: true,
      format: "json",
      ...params
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
    sessionsList: (params = {}) => this.request({
      path: `/stats/sessions`,
      method: "GET",
      secure: true,
      format: "json",
      ...params
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
    usersList: (params = {}) => this.request({
      path: `/stats/users`,
      method: "GET",
      secure: true,
      format: "json",
      ...params
    })
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
    usersCreate: (request, params = {}) => this.request({
      path: `/users`,
      method: "POST",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    queryCreate: (request, params = {}) => this.request({
      path: `/users/query`,
      method: "POST",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    usersDetail: (id, params = {}) => this.request({
      path: `/users/${id}`,
      method: "GET",
      secure: true,
      format: "json",
      ...params
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
    usersUpdate: (id, request, params = {}) => this.request({
      path: `/users/${id}`,
      method: "PUT",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    usersDelete: (id, params = {}) => this.request({
      path: `/users/${id}`,
      method: "DELETE",
      secure: true,
      format: "json",
      ...params
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
    emailConfirmedUpdate: (id, request, params = {}) => this.request({
      path: `/users/${id}/email-confirmed`,
      method: "PUT",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    identitiesDetail: (id, params = {}) => this.request({
      path: `/users/${id}/identities`,
      method: "GET",
      secure: true,
      format: "json",
      ...params
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
    identitiesDelete: (id, identityId, params = {}) => this.request({
      path: `/users/${id}/identities/${identityId}`,
      method: "DELETE",
      secure: true,
      format: "json",
      ...params
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
    phoneConfirmedUpdate: (id, request, params = {}) => this.request({
      path: `/users/${id}/phone-confirmed`,
      method: "PUT",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    resetPasswordCreate: (id, request, params = {}) => this.request({
      path: `/users/${id}/reset-password`,
      method: "POST",
      body: request,
      secure: true,
      type: "application/json" /* Json */,
      format: "json",
      ...params
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
    sessionsDetail: (id, query, params = {}) => this.request({
      path: `/users/${id}/sessions`,
      method: "GET",
      query,
      secure: true,
      format: "json",
      ...params
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
    sessionsDelete: (id, params = {}) => this.request({
      path: `/users/${id}/sessions`,
      method: "DELETE",
      secure: true,
      format: "json",
      ...params
    })
  };
}
export {
  Api,
  ContentType,
  GithubComThecybersailorSlauthPkgTypesAALLevel,
  GithubComThecybersailorSlauthPkgTypesFactorStatus,
  GithubComThecybersailorSlauthPkgTypesFactorType,
  HttpClient,
  TimeDuration
};
