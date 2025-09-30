# Changelog

All notable changes to Slauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2025-09-30

### Initial Open Source Release

This is the first public release of Slauth, a flexible authentication library for Go applications.

### Added

#### Core Authentication
- Email/Password authentication with secure password hashing
- OAuth 2.0 integration (Google, Facebook)
- SAML 2.0 SSO support with attribute mapping
- One-Time Password (OTP) authentication via email and SMS
- Magic link authentication
- Multi-Factor Authentication (TOTP) support
- Session management with automatic token refresh
- JWT-based authentication tokens

#### Security Features
- Rate limiting for authentication endpoints
- Configurable password strength requirements
- Account lockout protection
- Email verification
- Password reset functionality
- IP-based signup filtering
- Captcha integration (Cloudflare Turnstile)

#### Database Support
- PostgreSQL support
- MySQL/MariaDB support
- SQLite support
- GORM-based database abstraction
- Database migration support

#### Admin Features
- User management API
- Session management
- Identity provider management
- System statistics and monitoring
- Bulk user operations
- User metadata management

#### Frontend Packages
- TypeScript SDK (`@cybersailor/slauth-ts`)
  - Type-safe API client
  - Automatic token refresh
  - Session management
  - Auth state listeners
  - PKCE OAuth flow support
- Vue 3 UI Components (`@cybersailor/slauth-ui-vue`)
  - Pre-built auth forms
  - OAuth provider buttons
  - Password strength indicators
  - Customizable themes
  - Localization support
  - Admin dashboard components
  - User profile management

#### Email & SMS
- Template-based email system
- Customizable email templates
- SMS integration (AWS SNS, Twilio)
- Built-in template resolver
- Support for custom template providers

#### Developer Experience
- Comprehensive documentation
- 100% test coverage
- Example demo application
- OpenAPI specifications
- Type generation from API specs
- Makefile for build automation

#### Extensibility
- Pluggable authentication providers
- Custom email/SMS providers
- Hooks for custom business logic
- Flexible configuration system

### Security Notes

- All passwords are hashed using bcrypt
- JWTs are signed and validated
- Rate limiting is enabled by default
- CORS is configurable
- Secure session management

### Database Schema

Initial database schema includes:
- users
- identities
- sessions
- refresh_tokens
- mfa_factors
- mfa_challenges
- one_time_tokens
- sso_providers
- saml_relay_states
- flow_states

### Known Limitations

- WebAuthn/Passkey support not yet implemented
- Phone number authentication is SMS-based only
- No built-in GraphQL API (REST only)
- Account linking requires manual implementation

### Migration Notes

This is the first public release, so no migration is needed.

### Upgrade Notes

Not applicable for initial release.

## Release Checklist

For maintainers preparing a release:

- [ ] Update version numbers in all package.json files
- [ ] Update this CHANGELOG.md
- [ ] Run full test suite (`make test`, `make test-mysql`, `make test-pgsql`)
- [ ] Build all packages (`make clean && make all`)
- [ ] Update documentation if needed
- [ ] Create git tag (`git tag v0.8.0`)
- [ ] Push tag (`git push origin v0.8.0`)
- [ ] Publish npm packages
- [ ] Create GitHub release with notes

---

[Unreleased]: https://github.com/thecybersailor/slauth/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/thecybersailor/slauth/releases/tag/v0.8.0
