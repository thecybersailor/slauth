package consts

import "github.com/flaboy/pin/usererrors"

// Do not add new errors, must use the following error types

var (
	// Anonymous sign-ins are disabled.
	ANONYMOUS_PROVIDER_DISABLED = usererrors.New("auth.anonymous_provider_disabled", "Anonymous sign-in is currently disabled. Please use another sign-in method.")

	// Returned from the PKCE flow where the provided code verifier does not match the expected one. Indicates a bug in the implementation of the client library.
	BAD_CODE_VERIFIER = usererrors.New("auth.bad_code_verifier", "Verification code mismatch. Please try signing in again.")

	// Usually used when the HTTP body Sf the request is not valid JSON.
	BAD_JSON = usererrors.New("auth.bad_json", "Invalid request format. Please check your input and try again.")

	// JWT sent in the Authorization header is not valid.
	BAD_JWT = usererrors.New("auth.bad_jwt", "Invalid token").SetHttpStatus(401)

	// OAuth callback from provider to Auth does not have all the required attributes (state). Indicates an issue with the OAuth provider or client library implementation.
	BAD_OAUTH_CALLBACK = usererrors.New("auth.bad_oauth_callback", "OAuth sign-in failed. Please try signing in again.")

	// OAuth state (data echoed back by the OAuth provider to auth Auth) is not in the correct format. Indicates an issue with the OAuth provider integration.
	BAD_OAUTH_STATE = usererrors.New("auth.bad_oauth_state", "OAuth verification failed. Please restart the sign-in process.")

	// CAPTCHA challenge could not be verified with the CAPTCHA provider. Check your CAPTCHA integration.
	CAPTCHA_FAILED = usererrors.New("auth.captcha_failed", "CAPTCHA verification failed. Please try again with a new CAPTCHA.")

	// General database conflict, such as concurrent requests on resources that should not be modified concurrently. Can often occur when you have too many session refresh requests firing off at the same time for a user. Check your app for concurrency issues, and if detected, back off exponentially.
	CONFLICT = usererrors.New("auth.conflict", "Too many simultaneous requests. Please wait a moment and try again.")

	// Example and test instances are currently not supported. Use a different email address.
	EMAIL_ADDRESS_INVALID = usererrors.New("auth.email_address_invalid", "This email address is not supported. Please use a different email.")

	// Email sending is not allowed for this address as your project is using the default SMTP service. Emails can only be sent to members in your auth organization. If you want to send emails to others, set up a custom SMTP provider.
	EMAIL_ADDRESS_NOT_AUTHORIZED = usererrors.New("auth.email_address_not_authorized", "Email not authorized. Please contact support for assistance.")

	// Unlinking this identity causes the user's account to change to an email address which is already used by another user account. Indicates an issue where the user has two different accounts using different primary email addresses. You may need to migrate user data to one of their accounts in this case.
	EMAIL_CONFLICT_IDENTITY_NOT_DELETABLE = usererrors.New("auth.email_conflict_identity_not_deletable", "Email already linked to another account. Please contact support.")

	// Email address already exists in the system.
	EMAIL_EXISTS = usererrors.New("auth.email_exists", "Email already registered. Please sign in or use a different email.")

	// Signing in is not allowed for this user as the email address is not confirmed.
	EMAIL_NOT_CONFIRMED = usererrors.New("auth.email_not_confirmed", "Email not verified. Please check your inbox and verify your email.")

	// Signups are disabled for email and password.
	EMAIL_PROVIDER_DISABLED = usererrors.New("auth.email_provider_disabled", "Email sign-up is disabled. Please use another sign-in method.")

	// New user signups are disabled for this project.
	SIGNUPS_DISABLED = usererrors.New("auth.signups_disabled", "New user registration is disabled. Please contact support.")

	// PKCE flow state to which the API request relates has expired. Ask the user to sign in again.
	FLOW_STATE_EXPIRED = usererrors.New("auth.flow_state_expired", "Sign-in session expired. Please start the sign-in process again.")

	// PKCE flow state to which the API request relates no longer exists. Flow states expire after a while and are progressively cleaned up, which can cause this error. Retried requests can cause this error, as the previous request likely destroyed the flow state. Ask the user to sign in again.
	FLOW_STATE_NOT_FOUND = usererrors.New("auth.flow_state_not_found", "Sign-in session lost. Please try signing in again.")

	// Payload from Auth does not have a valid Content-Type header.
	HOOK_PAYLOAD_INVALID_CONTENT_TYPE = usererrors.New("auth.hook_payload_invalid_content_type", "Invalid request type. Please try again.")

	// Payload from Auth exceeds maximum size limit.
	HOOK_PAYLOAD_OVER_SIZE_LIMIT = usererrors.New("auth.hook_payload_over_size_limit", "Request too large. Please reduce data size and try again.")

	// Unable to reach hook within maximum time allocated.
	HOOK_TIMEOUT = usererrors.New("auth.hook_timeout", "Request timed out. Please try again.")

	// Unable to reach hook after maximum number of retries.
	HOOK_TIMEOUT_AFTER_RETRY = usererrors.New("auth.hook_timeout_after_retry", "Connection failed. Please check your network and try again.")

	// The identity to which the API relates is already linked to a user.
	IDENTITY_ALREADY_EXISTS = usererrors.New("auth.identity_already_exists", "Account already linked. Please try a different account.")

	// Identity to which the API call relates does not exist, such as when an identity is unlinked or deleted.
	IDENTITY_NOT_FOUND = usererrors.New("auth.identity_not_found", "Account connection not found. Please sign in again.")

	// To call this API, the user must have a higher Authenticator Assurance Level. To resolve, ask the user to solve an MFA challenge.
	INSUFFICIENT_AAL = usererrors.New("auth.insufficient_aal", "Additional authentication required. Please complete MFA verification.")

	// MFA
	// Login credentials or grant type not recognized.
	INVALID_CREDENTIALS = usererrors.New("auth.invalid_credentials", "Incorrect username or password. Please try again.")

	// Invite is expired or already used.
	INVITE_NOT_FOUND = usererrors.New("auth.invite_not_found", "Invite expired or already used. Please request a new invite.")

	// Calling the auth.auth.linkUser() and related APIs is not enabled on the Auth server.
	MANUAL_LINKING_DISABLED = usererrors.New("auth.manual_linking_disabled", "Account linking not available. Please contact support.")

	// Responding to an MFA challenge should happen within a fixed time period. Request a new challenge when encountering this error.
	MFA_CHALLENGE_EXPIRED = usererrors.New("auth.mfa_challenge_expired", "MFA code expired. Please request a new code.")

	// MFA factors for a single user should not have the same friendly name.
	MFA_FACTOR_NAME_CONFLICT = usererrors.New("auth.mfa_factor_name_conflict", "MFA name already exists. Please choose a different name.")

	// MFA factor no longer exists.
	MFA_FACTOR_NOT_FOUND = usererrors.New("auth.mfa_factor_not_found", "MFA method not found. Please set up MFA again.")

	// The enrollment process for MFA factors must begin and end with the same IP address.
	MFA_IP_ADDRESS_MISMATCH = usererrors.New("auth.mfa_ip_address_mismatch", "IP address changed. Please restart MFA setup.")

	// Enrollment of MFA Phone factors is disabled.
	MFA_PHONE_ENROLL_NOT_ENABLED = usererrors.New("auth.mfa_phone_enroll_not_enabled", "Phone MFA not available. Please use another MFA method.")

	// Login via Phone factors and verification of new Phone factors is disabled.
	MFA_PHONE_VERIFY_NOT_ENABLED = usererrors.New("auth.mfa_phone_verify_not_enabled", "Phone verification disabled. Please use another verification method.")

	// Enrollment of MFA TOTP factors is disabled.
	MFA_TOTP_ENROLL_NOT_ENABLED = usererrors.New("auth.mfa_totp_enroll_not_enabled", "TOTP MFA not available. Please use another MFA method.")

	// Login via TOTP factors and verification of new TOTP factors is disabled.
	MFA_TOTP_VERIFY_NOT_ENABLED = usererrors.New("auth.mfa_totp_verify_not_enabled", "TOTP verification disabled. Please use another verification method.")

	// MFA challenge could not be verified -- wrong TOTP code.
	MFA_VERIFICATION_FAILED = usererrors.New("auth.mfa_verification_failed", "Incorrect MFA code. Please try again.")

	// Further MFA verification is rejected. Only returned if the MFA verification attempt hook returns a reject decision.
	MFA_VERIFICATION_REJECTED = usererrors.New("auth.mfa_verification_rejected", "MFA verification denied. Please contact support.")

	// Verified phone factor already exists for a user. Unenroll existing verified phone factor to continue.
	MFA_VERIFIED_FACTOR_EXISTS = usererrors.New("auth.mfa_verified_factor_exists", "Phone already verified. Please remove existing phone first.")

	// Enrollment of MFA Web Authn factors is disabled.
	MFA_WEB_AUTHN_ENROLL_NOT_ENABLED = usererrors.New("auth.mfa_web_authn_enroll_not_enabled", "WebAuthn not available. Please use another MFA method.")

	// Login via WebAuthn factors and verification of new WebAuthn factors is disabled.
	MFA_WEB_AUTHN_VERIFY_NOT_ENABLED = usererrors.New("auth.mfa_web_authn_verify_not_enabled", "WebAuthn verification disabled. Please use another method.")

	// This HTTP request requires an Authorization header, which is not provided.
	NO_AUTHORIZATION = usererrors.New("auth.no_authorization", "Missing authorization token").SetHttpStatus(401)

	// User accessing the API is not admin, i.e. the JWT does not contain a role claim that identifies them as an admin of the Auth server.
	NOT_ADMIN = usererrors.New("auth.not_admin", "Admin access required. Please sign in with an admin account.").SetHttpStatus(401)

	// Using an OAuth provider which is disabled on the Auth server.
	OAUTH_PROVIDER_NOT_SUPPORTED = usererrors.New("auth.oauth_provider_not_supported", "This sign-in method is disabled. Please use another method.")

	// Sign in with OTPs (magic link, email OTP) is disabled. Check your server's configuration.
	OTP_DISABLED = usererrors.New("auth.otp_disabled", "One-time passwords disabled. Please use another sign-in method.")

	// OTP code for this sign-in has expired. Ask the user to sign in again.
	OTP_EXPIRED = usererrors.New("auth.otp_expired", "Verification code expired. Please request a new code.")

	// Too many emails have been sent to this email address. Ask the user to wait a while before trying again.
	OVER_EMAIL_SEND_RATE_LIMIT = usererrors.New("auth.over_email_send_rate_limit", "Too many emails sent. Please wait a few minutes and try again.")

	// Too many requests have been sent by this client (IP address). Ask the user to try again in a few minutes. Sometimes can indicate a bug in your application that mistakenly sends out too many requests (such as a badly written useEffect React hook).
	OVER_REQUEST_RATE_LIMIT = usererrors.New("auth.over_request_rate_limit", "Too many attempts. Please wait a few minutes and try again.")

	// Too many SMS messages have been sent to this phone number. Ask the user to wait a while before trying again.
	OVER_SMS_SEND_RATE_LIMIT = usererrors.New("auth.over_sms_send_rate_limit", "Too many SMS sent. Please wait a few minutes and try again.")

	// Phone number already exists in the system.
	PHONE_EXISTS = usererrors.New("auth.phone_exists", "Phone number already registered. Please use a different number.")

	// Signing in is not allowed for this user as the phone number is not confirmed.
	PHONE_NOT_CONFIRMED = usererrors.New("auth.phone_not_confirmed", "Phone not verified. Please verify your phone number.")

	// Signups are disabled for phone and password.
	PHONE_PROVIDER_DISABLED = usererrors.New("auth.phone_provider_disabled", "Phone sign-up is disabled. Please use another sign-in method.")

	// OAuth provider is disabled for use. Check your server's configuration.
	PROVIDER_DISABLED = usererrors.New("auth.provider_disabled", "This sign-in method is disabled. Please use another method.")

	// Not all OAuth providers verify their user's email address. auth Auth requires emails to be verified, so this error is sent out when a verification email is sent after completing the OAuth flow.
	PROVIDER_EMAIL_NEEDS_VERIFICATION = usererrors.New("auth.provider_email_needs_verification", "Please verify your email to continue.")

	// A user needs to reauthenticate to change their password. Ask the user to reauthenticate by calling the auth.auth.reauthenticate() API.
	REAUTHENTICATION_NEEDED = usererrors.New("auth.reauthentication_needed", "Please sign in again to continue.")

	// Verifying a reauthentication failed, the code is incorrect. Ask the user to enter a new code.
	REAUTHENTICATION_NOT_VALID = usererrors.New("auth.reauthentication_not_valid", "Invalid verification code. Please try again.")

	// Refresh token has been revoked and falls outside the refresh token reuse interval. See the documentation on sessions for further information.
	REFRESH_TOKEN_ALREADY_USED = usererrors.New("auth.refresh_token_already_used", "Session expired. Please sign in again.").SetHttpStatus(401)

	// Session containing the refresh token not found.
	REFRESH_TOKEN_NOT_FOUND = usererrors.New("auth.refresh_token_not_found", "Session not found. Please sign in again.").SetHttpStatus(401)

	// Processing the request took too long. Retry the request.
	REQUEST_TIMEOUT = usererrors.New("auth.request_timeout", "Request timed out. Please try again.")

	// A user that is updating their password must use a different password than the one currently used.
	SAME_PASSWORD = usererrors.New("auth.same_password", "Please choose a different password than your current one.")

	// SAML assertion (user information) was received after sign in, but no email address was found in it, which is required. Check the provider's attribute mapping and/or configuration.
	SAML_ASSERTION_NO_EMAIL = usererrors.New("auth.saml_assertion_no_email", "SSO email missing. Please contact your IT administrator.")

	// SAML assertion (user information) was received after sign in, but a user ID (called NameID) was not found in it, which is required. Check the SAML identity provider's configuration.
	SAML_ASSERTION_NO_USER_ID = usererrors.New("auth.saml_assertion_no_user_id", "SSO ID missing. Please contact your IT administrator.")

	// (Admin API.) Updating the SAML metadata for a SAML identity provider is not possible, as the entity ID in the update does not match the entity ID in the database. This is equivalent to creating a new identity provider, and you should do that instead.
	SAML_ENTITY_ID_MISMATCH = usererrors.New("auth.saml_entity_id_mismatch", "SSO configuration error. Please contact support.")

	// (Admin API.) Adding a SAML identity provider that is already added.
	SAML_IDP_ALREADY_EXISTS = usererrors.New("auth.saml_idp_already_exists", "SSO provider already exists. Please use a different one.")

	// SAML identity provider not found. Most often returned after IdP-initiated sign-in with an unregistered SAML identity provider in auth Auth.
	SAML_IDP_NOT_FOUND = usererrors.New("auth.saml_idp_not_found", "SSO provider not found. Please check your settings.")

	// (Admin API.) Adding or updating a SAML provider failed as its metadata could not be fetched from the provided URL.
	SAML_METADATA_FETCH_FAILED = usererrors.New("auth.saml_metadata_fetch_failed", "SSO setup failed. Please check the provider URL.")

	// Using Enterprise SSO with SAML 2.0 is not enabled on the Auth server.
	SAML_PROVIDER_DISABLED = usererrors.New("auth.saml_provider_disabled", "SSO is disabled. Please use another sign-in method.")

	// SAML relay state is an object that tracks the progress of a auth.auth.signInWithSSO() request. The SAML identity provider should respond after a fixed amount of time, after which this error is shown. Ask the user to sign in again.
	SAML_RELAY_STATE_EXPIRED = usererrors.New("auth.saml_relay_state_expired", "SSO session expired. Please try signing in again.")

	// SAML relay states are progressively cleaned up after they expire, which can cause this error. Ask the user to sign in again.
	SAML_RELAY_STATE_NOT_FOUND = usererrors.New("auth.saml_relay_state_not_found", "SSO session lost. Please try signing in again.")

	// Session to which the API request relates has expired. This can occur if an inactivity timeout is configured, or the session entry has exceeded the configured timebox value. See the documentation on sessions for more information.
	SESSION_EXPIRED = usererrors.New("auth.session_expired", "Session expired. Please sign in again.").SetHttpStatus(401)

	// Session to which the API request relates no longer exists. This can occur if the user has signed out, or the session entry in the database was deleted in some other way.
	SESSION_NOT_FOUND = usererrors.New("auth.session_not_found", "Session not found. Please sign in again.").SetHttpStatus(401)

	// Sign ups (new account creation) are disabled on the server.
	SIGNUP_DISABLED = usererrors.New("auth.signup_disabled", "Sign-up is currently disabled. Please contact support.")

	// Every user must have at least one identity attached to it, so deleting (unlinking) an identity is not allowed if it's the only one for the user.
	SINGLE_IDENTITY_NOT_DELETABLE = usererrors.New("auth.single_identity_not_deletable", "Cannot remove last login method. Please add another first.")

	// Sending an SMS message failed. Check your SMS provider configuration.
	SMS_SEND_FAILED = usererrors.New("auth.sms_send_failed", "SMS delivery failed. Please try again or contact support.")

	// (Admin API.) Only one SSO instance can be registered per SSO identity provider.
	SSO_DOMAIN_ALREADY_EXISTS = usererrors.New("auth.sso_instance_already_exists", "SSO instance already registered. Please use a different instance.")

	// SSO provider not found. Check the arguments in auth.auth.signInWithSSO().
	SSO_PROVIDER_NOT_FOUND = usererrors.New("auth.sso_provider_not_found", "SSO provider not found. Please check your settings.")

	// A user can only have a fixed number of enrolled MFA factors.
	TOO_MANY_ENROLLED_MFA_FACTORS = usererrors.New("auth.too_many_enrolled_mfa_factors", "Too many MFA methods. Please remove one first.")

	// (Deprecated feature not available via auth client libraries.) The request's X-JWT-AUD claim does not match the JWT's audience.
	UNEXPECTED_AUDIENCE = usererrors.New("auth.unexpected_audience", "Invalid request target. Please try again.")

	// Auth service is degraded or a bug is present, without a specific reason.
	UNEXPECTED_FAILURE = usererrors.New("auth.unexpected_failure", "Something went wrong. Please try again or contact support.")

	// User with this information (email address, phone number) cannot be created again as it already exists.
	USER_ALREADY_EXISTS = usererrors.New("auth.user_already_exists", "Account already exists. Please sign in instead.")

	// User to which the API request relates has a banned_until property which is still active. No further API requests should be attempted until // this field is cleared.
	USER_BANNED = usererrors.New("auth.user_banned", "Account temporarily suspended. Please try again later.")

	// User to which the API request relates no longer exists.
	USER_NOT_FOUND = usererrors.New("auth.user_not_found", "Account not found. Please check your credentials.").SetHttpStatus(401)

	// When a user comes from SSO, certain fields of the user cannot be updated (like email).
	USER_SSO_MANAGED = usererrors.New("auth.user_sso_managed", "Account managed by SSO. Please contact your IT administrator.")

	// Provided parameters are not in the expected format.
	VALIDATION_FAILED = usererrors.New("auth.validation_failed", "Invalid input. Please check your information and try again.")

	// User is signing up or changing their password without meeting the password strength criteria. Use the AuthWeakPasswordError class to access more information about what they need to do to make the password pass.
	WEAK_PASSWORD = usererrors.New("auth.weak_password", "Password too weak. Please use a stronger password.")
)
