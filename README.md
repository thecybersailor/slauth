# Slauth

**Slauth** is a flexible, open-source authentication library for Go applications. Built as a library rather than a service, it offers the power of comprehensive authentication features with the flexibility to integrate seamlessly into your existing Go projects.

## Overview

Slauth provides enterprise-grade authentication capabilities similar to Supabase Auth, but designed specifically for the Go ecosystem. Whether you need simple email/password authentication or complex SAML SSO integrations, Slauth offers a modular, extensible architecture that grows with your needs.

### Why Slauth?

- **Library-First Design**: Integrate directly into your Go application instead of running a separate auth service
- **Highly Flexible**: Add custom authentication providers and extend functionality to match your requirements
- **Production Ready**: 100% test coverage with support for PostgreSQL, MySQL, and SQLite
- **Framework Agnostic**: Works with any Go web framework or HTTP router
- **Full-Featured**: From basic auth to MFA, SAML, and OAuth - everything you need is included

## Features

- Email/Password Authentication
- OAuth 2.0 Providers (Google, Facebook, and more)
- SAML 2.0 SSO Integration
- One-Time Password (OTP) via Email/SMS
- Multi-Factor Authentication (TOTP)
- Session Management with Auto-Refresh
- Customizable Authentication Providers
- Rate Limiting and Security Controls
- Custom Email Templates
- Multiple Database Support (PostgreSQL, MySQL, SQLite)
- Admin API for User Management
- TypeScript SDK and Vue 3 UI Components

## Quick Start

### Installation

```bash
go get github.com/thecybersailor/slauth
```

### Basic Usage

```go
package main

import (
    "github.com/thecybersailor/slauth/pkg/auth"
    "github.com/thecybersailor/slauth/pkg/config"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

func main() {
    // Initialize database
    db, err := gorm.Open(postgres.Open("your-database-url"), &gorm.Config{})
    if err != nil {
        panic(err)
    }

    // Configure authentication service
    cfg := &config.ServiceConfig{
        JWT: config.JWTConfig{
            Secret: "your-secret-key",
            Exp:    3600,
        },
        Security: config.SecurityConfig{
            PasswordMinLength: 8,
        },
    }

    // Create auth instance
    authService := auth.NewAuthService(db, cfg)

    // Use in your HTTP handlers
    // See documentation for complete examples
}
```

### Sign Up a User

```go
result, err := authService.SignUp(ctx, &types.SignUpRequest{
    Email:    "user@example.com",
    Password: "SecurePass123!",
})
if err != nil {
    // Handle error
}

// Access token and user information
accessToken := result.Session.AccessToken
user := result.User
```

### Sign In

```go
result, err := authService.SignInWithPassword(ctx, &types.SignInRequest{
    Email:    "user@example.com",
    Password: "SecurePass123!",
})
if err != nil {
    // Handle error
}
```

## Frontend Integration

Slauth provides official TypeScript and Vue.js packages for seamless frontend integration.

### TypeScript SDK

```bash
npm install @cybersailor/slauth-ts
```

```typescript
import { createClient } from '@cybersailor/slauth-ts'

const auth = createClient({
  url: 'http://localhost:8080',
  apiKey: 'your-api-key'
})

// Sign up
const { data, error } = await auth.signUp({
  email: 'user@example.com',
  password: 'Password123!'
})

// Listen to auth state changes
auth.onAuthStateChange((event, session) => {
  console.log(event, session)
})
```

### Vue 3 UI Components

```bash
npm install @cybersailor/slauth-ui-vue @cybersailor/slauth-ts
```

```vue
<template>
  <Auth
    :auth-client="authClient"
    appearance="default"
    theme="light"
    :providers="['google', 'github']"
  />
</template>

<script setup lang="ts">
import { createClient } from '@cybersailor/slauth-ts'
import { Auth } from '@cybersailor/slauth-ui-vue'
import '@cybersailor/slauth-ui-vue/style.css'

const authClient = createClient({
  url: 'http://localhost:8080',
  apiKey: 'your-api-key'
})
</script>
```

## Documentation

- [API Reference](./docs/specs/) - OpenAPI specifications for Auth and Admin APIs
- [Configuration Guide](./docs/) - Detailed configuration options
- [Custom Providers](./docs/) - How to implement custom authentication providers
- [Deployment Guide](./docs/) - Production deployment best practices
- [Examples](./demo/) - Full working examples

## Database Support

Slauth works with any database supported by GORM:

- PostgreSQL (Recommended for production)
- MySQL/MariaDB
- SQLite (Development/testing)

## Testing

Slauth maintains 100% test coverage. Run the test suite:

```bash
# Default (SQLite)
make test

# PostgreSQL
make test-pgsql

# MySQL
make test-mysql
```

## Architecture

```
slauth/
├── pkg/                    # Core Go library
│   ├── auth/              # Authentication service
│   ├── config/            # Configuration
│   ├── controller/        # HTTP handlers
│   ├── models/            # Database models
│   ├── services/          # Business logic
│   └── providers/         # Auth providers (OAuth, SAML, SMS, Email)
├── packages/
│   ├── slauth-ts/         # TypeScript SDK
│   └── slauth-ui-vue/     # Vue 3 UI components
├── tests/                 # Comprehensive test suite
└── templates/             # Email/SMS templates
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details on:

- Code of conduct
- Development setup
- Submitting pull requests
- Coding standards

## Security

Security is a top priority. If you discover a security vulnerability, please email us at [developer@cybersailor.ai](mailto:developer@cybersailor.ai). See [SECURITY.md](./SECURITY.md) for details.

## License

Slauth is licensed under a modified Apache License 2.0. See [LICENSE](./LICENSE) for the full license text.

Key points:
- Free to use for single-tenant applications
- Commercial license required for multi-tenant SaaS services
- Contributors grant rights for commercial use

## Comparison with Alternatives

| Feature | Slauth | Supabase Auth | Auth0 | Keycloak |
|---------|--------|---------------|-------|----------|
| Deployment | Go Library | Hosted Service | Hosted Service | Java Server |
| Language | Go | TypeScript | N/A | Java |
| Self-Hosted | Yes | Yes | Limited | Yes |
| Custom Providers | Yes | Limited | No | Yes |
| License | Apache 2.0* | MIT | Proprietary | Apache 2.0 |
| Database | Any (GORM) | PostgreSQL | N/A | Multiple |

## Roadmap

- WebAuthn/Passkey support
- Additional OAuth providers
- Phone authentication enhancements
- GraphQL API
- Account linking
- Anonymous users

## Community

- GitHub Issues: [Report bugs or request features](https://github.com/thecybersailor/slauth/issues)
- GitHub Discussions: [Ask questions and share ideas](https://github.com/thecybersailor/slauth/discussions)

## Sponsors

Slauth is developed and maintained by [CYBERSAILOR PTE. LTD.](https://cybersailor.ai)

## Acknowledgments

Inspired by the excellent work of the Supabase team and the broader authentication ecosystem.

---

Made with care by the CYBERSAILOR team.
