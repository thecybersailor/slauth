# Package Structure

Overview of Slauth Go package organization.

## adapters/

**Files:**

- mailer_adapter.go
  - struct: `MailerAdapter`
  - func: `NewMailerAdapter`

## auth/

**Files:**

- auth.go
  - struct: `ControllerRouteHandler`
    ControllerRouteHandler implements RouteHandler interface
  - struct: `AdminRouteHandler`
    AdminRouteHandler implements admin route handler
  - func: `NewAuthServiceConfig`
    NewAuthServiceConfig creates a new AuthServiceConfig with default values
  - func: `NewService`
    The service will automatically load dynamic config from database
  - func: `Start`

## config/

**Files:**

- ratelimit.go
  - struct: `RatelimitConfig`
    RatelimitConfig defines rate limiting configurations for various operations
  - struct: `RateLimit`
    RateLimit defines the structure for rate limiting configuration
  - func: `GetDefaultRatelimitConfig`
    GetDefaultRatelimitConfig returns the default rate limiting configuration
- security.go
  - struct: `AALPolicy`
  - struct: `SecurityConfig`
  - struct: `PasswordUpdateConfig`
  - struct: `PasswordStrengthConfig`
  - func: `GetDefaultSecurityConfig`
- service.go
  - struct: `AuthServiceConfig`
  - func: `NewDefaultAuthServiceConfig`
  - func: `NewAuthServiceConfig`
- session.go
  - struct: `SessionConfig`
  - func: `GetDefaultSessionConfig`
    GetDefaultSessionConfig returns the default session configuration

## consts/

**Files:**

- errors.go
- tmpl.go

## controller/

**Files:**

- admin_controller.go
  - struct: `AdminController`
    AdminController handles admin operations
  - struct: `QueryBuilder`
  - func: `NewAdminController`
    NewAdminController creates a new AdminController instance
  - func: `NewQueryBuilder`
- admin_saml_types.go
- admin_types.go
- auth_controller.go
  - struct: `AuthController`
    AuthController handles authentication operations based on auth auth-js API
  - func: `NewAuthController`
    NewAuthController creates a new AuthController instance
- auth_handlers.go
- auth_helpers.go
  - struct: `OAuthUserInfo`
    OAuthUserInfo represents user info from OAuth provider
- auth_types.go
- mfa_controller.go
- middleware.go
  - func: `JWTAuthMiddleware`
    JWTAuthMiddleware validates JWT tokens and sets user context
  - func: `OptionalJWTAuthMiddleware`
    OptionalJWTAuthMiddleware validates JWT tokens if present but doesn't require them
  - func: `RateLimitMiddleware`
    RateLimitMiddleware implements basic rate limiting
  - func: `CORSMiddleware`
    CORSMiddleware handles Cross-Origin Resource Sharing
  - func: `ErrorHandlerMiddleware`
    ErrorHandlerMiddleware handles errors and formats responses
  - func: `LoggingMiddleware`
    LoggingMiddleware logs requests
  - func: `RecoveryMiddleware`
    RecoveryMiddleware recovers from panics
  - func: `PinContextAdapter`
    PinContextAdapter adapts gin.Context to pin.Context for middleware compatibility
- oauth_handlers.go
- password_handler.go
- routes.go
  - func: `RegisterRoutes`
  - func: `RegisterAdminRoutes`
    RegisterAdminRoutes registers admin-related routes
- signin_handler.go
- signup_handler.go
- token_handlers.go
  - struct: `RevokeTokenRequest`
  - struct: `IntrospectTokenRequest`
  - struct: `IntrospectTokenResponse`
- user_controller.go
  - struct: `UserController`
    UserController handles user management operations
  - struct: `UpdateUserRequest`
  - struct: `UpdateUserOptions`
  - struct: `UserData`
  - struct: `ResendRequest`
  - struct: `ResendOptions`
  - struct: `SessionData`
    Session management types
  - struct: `ResendData`
  - struct: `SetSessionRequest`

## docs/

**Files:**


## flow/

**Files:**


## models/

**Files:**

- auth_instance.go
  - struct: `AuthInstance`
- flow_state.go
  - struct: `FlowState`
- identity.go
  - struct: `Identity`
- json_type.go
- mfa_amr_claim.go
  - struct: `MFAAMRClaim`
- mfa_challenge.go
  - struct: `MFAChallenge`
- mfa_factor.go
  - struct: `MFAFactor`
- models.go
  - func: `Init`
  - func: `AllModels`
    AllModels returns a slice of all auth models for migration purposes
  - func: `AutoMigrate`
    AutoMigrate runs auto migration for all auth models
  - func: `CreateSchema`
    CreateSchema creates the auth schema if it doesn't exist
- one_time_token.go
  - struct: `OneTimeToken`
- refresh_token.go
  - struct: `RefreshToken`
- saml_relay_state.go
  - struct: `SAMLRelayState`
- session.go
  - struct: `Session`
- sso_provider.go
  - struct: `SSOProvider`
  - struct: `SAMLProvider`
  - struct: `SSOInstance`
- user.go
  - struct: `User`

## providers/

**Files:**


## registry/

**Files:**

- auth_registry.go
  - func: `RegisterAuthService`
  - func: `GetAuthService`

## services/

**Files:**

- admin_identity_service.go
  - struct: `AdminIdentityService`
    AdminIdentityService provides admin operations for identity management
  - struct: `UserIdentity`
  - func: `NewUserIdentity`
    NewUserIdentity creates a new UserIdentity object
  - func: `NewAdminIdentityService`
    NewAdminIdentityService creates a new admin identity service
- admin_session_service.go
  - struct: `AdminSessionService`
    AdminSessionService provides admin operations for session management
  - func: `NewAdminSessionService`
    NewAdminSessionService creates a new admin session service
- admin_system_service.go
  - struct: `AdminSystemService`
    AdminSystemService provides admin operations for system management
  - func: `NewAdminSystemService`
    NewAdminSystemService creates a new admin system service
- auth_context.go
  - struct: `AuthContext`
  - func: `GetAuthContext`
  - func: `SetAuthContext`
- auth_service.go
  - interface: `RouteHandler`
  - interface: `AuthService`
- auth_service_impl.go
  - struct: `SessionStats`
    SessionStats represents session statistics
  - struct: `AuthServiceImpl`
    AuthServiceImpl implements authentication business logic
  - struct: `InternalMessageTemplate`
    InternalMessageTemplate internal template implementation, unified rendering logic
  - func: `NewAuthServiceImpl`
    This is an internal implementation, use auth.NewService() instead
- builtin_template_resolver.go
  - struct: `BuiltinTemplateResolver`
  - func: `NewBuiltinTemplateResolver`
- config_loader.go
  - struct: `ConfigLoader`
  - func: `NewConfigLoader`
- file_template_resolver.go
  - struct: `FileTemplateResolver`
  - func: `NewFileTemplateResolver`
- hashid.go
- jwt_service.go
  - struct: `JWTClaims`
    JWTClaims represents the JWT claims structure
  - struct: `JWTService`
    JWTService handles JWT token operations
  - func: `NewJWTService`
    NewJWTService creates a new JWT service
  - func: `ExtractTokenFromHeader`
    ExtractTokenFromHeader extracts JWT token from Authorization header
- message_render.go
  - struct: `TemplateInfo`
  - struct: `MessageRenderService`
  - func: `NewMessageRenderService`
- mfa_service.go
  - struct: `MFAFactorService`
    MFAFactorService provides database operations for MFAFactor model
  - struct: `MFAChallengeService`
    MFAChallengeService provides database operations for MFAChallenge model
  - func: `NewMFAFactorService`
    NewMFAFactorService creates a new MFA factor service
  - func: `NewMFAChallengeService`
    NewMFAChallengeService creates a new MFA challenge service
- one_time_token_service.go
  - struct: `OneTimeTokenService`
    OneTimeTokenService provides database operations for OneTimeToken model
  - func: `NewOneTimeTokenService`
    NewOneTimeTokenService creates a new one-time token service
- otp_service.go
  - struct: `OTPService`
    OTPService handles OTP operations
  - func: `NewOTPService`
    NewOTPService creates a new OTP service
- password_service.go
  - struct: `PasswordConfig`
    PasswordConfig holds password hashing configuration
  - struct: `PasswordService`
    PasswordService handles password operations
  - func: `DefaultPasswordConfig`
    DefaultPasswordConfig returns default password hashing configuration
  - func: `NewPasswordService`
    NewPasswordService creates a new password service
- rate_limit_service.go
  - struct: `RateLimitService`
  - func: `NewRateLimitService`
- redirect_service.go
  - struct: `RedirectService`
    RedirectService handles redirect URL validation and processing
  - func: `NewRedirectService`
    NewRedirectService creates a new redirect service
- refresh_token_service.go
  - struct: `RefreshTokenService`
    RefreshTokenService provides database operations for RefreshToken model
  - func: `NewRefreshTokenService`
    NewRefreshTokenService creates a new refresh token service
- saml_service.go
  - struct: `SAMLService`
    SAMLService handles SAML SSO operations
  - struct: `SAMLRelayStateOptions`
    SAMLRelayStateOptions contains options for creating relay state
  - struct: `SSOProvider`
  - struct: `SAMLProvider`
  - func: `NewCertService`
    NewCertService creates a new certificate service
  - func: `NewSAMLService`
    NewSAMLService creates a new SAML service
- session_service.go
  - struct: `SessionService`
    SessionService provides database operations for Session model
  - struct: `Session`
  - func: `NewSessionService`
    NewSessionService creates a new session service
- signup_types.go
- token_utils.go
  - func: `GenerateSecureToken`
    GenerateSecureToken generates a cryptographically secure random token
  - func: `HashToken`
    HashToken creates a SHA256 hash of the token for secure storage
  - func: `GenerateConfirmationToken`
    Returns: (token, tokenHash, error)
  - func: `VerifyToken`
    VerifyToken verifies if a plain token matches the stored hash
- user_service.go
- validator_service.go
  - struct: `ValidatorService`
    ValidatorService handles input validation
  - func: `NewValidatorService`
    NewValidatorService creates a new validator service

## types/

**Files:**

- const.go
- hooks.go
  - interface: `User`
  - interface: `MFAFactor`
- message.go
  - interface: `MessageTemplateResolver`
  - interface: `MessageTemplate`
  - interface: `MessageRender`
  - interface: `MessageRenderResult`
  - struct: `FileTemplateResult`
- provider.go
- requests.go
- responses.go
