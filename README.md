# Slauth

[![CI Status](https://github.com/thecybersailor/slauth/actions/workflows/ci.yml/badge.svg)](https://github.com/thecybersailor/slauth/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/thecybersailor/slauth)](https://goreportcard.com/report/github.com/thecybersailor/slauth)
[![codecov](https://codecov.io/gh/thecybersailor/slauth/branch/main/graph/badge.svg)](https://codecov.io/gh/thecybersailor/slauth)
[![Go Reference](https://pkg.go.dev/badge/github.com/thecybersailor/slauth.svg)](https://pkg.go.dev/github.com/thecybersailor/slauth)
[![GitHub release](https://img.shields.io/github/release/thecybersailor/slauth.svg)](https://github.com/thecybersailor/slauth/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/thecybersailor/slauth.svg?style=social&label=Star)](https://github.com/thecybersailor/slauth)
[![GitHub issues](https://img.shields.io/github/issues/thecybersailor/slauth.svg)](https://github.com/thecybersailor/slauth/issues)

**Slauth** is a flexible, open-source authentication library for Go applications. Built as a library rather than a service, it offers the power of comprehensive authentication features with the flexibility to integrate seamlessly into your existing Go projects.

## Overview

Slauth provides enterprise-grade authentication capabilities similar to Supabase Auth, but designed specifically for the Go ecosystem. Whether you need simple email/password authentication or complex SAML SSO integrations, Slauth offers a modular, extensible architecture that grows with your needs.

### Why Slauth?

- **Library-First Design**: Integrate directly into your Go application instead of running a separate auth service
- **Multi-Tenant Architecture**: Create multiple isolated auth services for different user types (customers, vendors, staff, admins) with independent configurations
- **Highly Flexible**: Add custom authentication providers and extend functionality to match your requirements
- **Production Ready**: Comprehensive test coverage with support for PostgreSQL, MySQL, and SQLite
- **Framework Agnostic**: Works with any Go web framework or HTTP router
- **Full-Featured**: From basic auth to MFA, SAML, and OAuth - everything you need is included

## Features

### Core Authentication
- Email/Password Authentication
- OAuth 2.0 Providers (Google, Facebook, and more)
- SAML 2.0 SSO Integration
- One-Time Password (OTP) via Email/SMS
- Multi-Factor Authentication (TOTP)
- Magic Link Authentication

### Multi-Tenant Architecture
- **Multiple Isolated Services**: Create separate auth services for customers, vendors, staff, admins
- **Cross-Service Access Control**: Use RequestValidator() to control which service can access which resources
- **Flexible Admin Hierarchy**: Staff manages customers/vendors, admins manage everything - all controlled by validators
- **Independent Configurations**: Each service has its own OAuth apps, CAPTCHA settings, SMS providers
- **Runtime Configuration**: All settings stored in database, modifiable without code changes

### Developer Experience
- Session Management with Auto-Refresh
- Customizable Authentication Providers
- Rate Limiting and Security Controls
- Custom Email Templates
- Multiple Database Support (PostgreSQL, MySQL, SQLite)
- Admin API for User Management
- TypeScript SDK and Vue 3 UI Components
- Comprehensive Test Suite

## Quick Start

### Installation

```bash
go get github.com/thecybersailor/slauth
```

### Basic Single-Tenant Setup

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/gin-gonic/gin"
    "github.com/thecybersailor/slauth/pkg/auth"
)

func main() {
    // Initialize auth system
    if err := auth.Start(); err != nil {
        panic(err)
    }
    
    // Create Gin router
    r := gin.Default()
    
    // Global secrets (store securely in production)
    jwtSecret := "your-jwt-secret-change-in-production"
    appSecret := "your-app-secret-change-in-production"
    
    // Create auth service for your users
    authService := auth.NewService("users", jwtSecret, appSecret)
    
    // Register auth routes
    authService.HandleAuthRequest(r.Group("/auth"))   // User authentication endpoints
    authService.HandleAdminRequest(r.Group("/admin")) // Admin management endpoints
    
    // Start server
    log.Fatal(http.ListenAndServe(":8080", r))
}
```

## Multi-Tenant Architecture

Slauth's standout feature is its **multi-tenant architecture** - create multiple isolated auth services for different user types with independent configurations.

### Multi-Service Setup with Cross-Service Access Control

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/gin-gonic/gin"
    "github.com/thecybersailor/slauth/pkg/auth"
    "github.com/thecybersailor/slauth/pkg/providers/identidies/google"
)

func main() {
    if err := auth.Start(); err != nil {
        panic(err)
    }
    
    r := gin.Default()
    
    // Global secrets
    jwtSecret := "your-jwt-secret"
    appSecret := "your-app-secret"
    
    // Customer authentication service
    customerAuth := auth.NewService("customer", jwtSecret, appSecret).
        AddIdentityProvider(google.NewGoogleProvider(&google.GoogleOAuthConfig{
            ClientID:     "customer-google-client-id",
            ClientSecret: "customer-google-secret",
        }))
    
    customerAuth.HandleAuthRequest(r.Group("/customer/auth"))
    customerAuth.HandleAdminRequest(r.Group("/customer/admin"))
    
    // Vendor authentication service
    vendorAuth := auth.NewService("vendor", jwtSecret, appSecret).
        AddIdentityProvider(google.NewGoogleProvider(&google.GoogleOAuthConfig{
            ClientID:     "vendor-google-client-id",
            ClientSecret: "vendor-google-secret",
        }))
    
    vendorAuth.HandleAuthRequest(r.Group("/vendor/auth"))
    vendorAuth.HandleAdminRequest(r.Group("/vendor/admin"))
    
    // Staff authentication service
    staffAuth := auth.NewService("staff", jwtSecret, appSecret)
    staffAuth.HandleAuthRequest(r.Group("/staff/auth"))
    staffAuth.HandleAdminRequest(r.Group("/staff/admin"))
    
    // Admin authentication service
    adminAuth := auth.NewService("admin", jwtSecret, appSecret)
    adminAuth.HandleAuthRequest(r.Group("/admin/auth"))
    adminAuth.HandleAdminRequest(r.Group("/admin/admin"))
    
    // ========== Cross-Service Access Control ==========
    
    // Customer protected routes - only customers can access
    customerRoutes := r.Group("/api/customer")
    customerRoutes.Use(customerAuth.RequestValidator()) // Validates customer JWT
    {
        customerRoutes.GET("/orders", getMyOrders)           // Customer's own orders
        customerRoutes.GET("/profile", getMyProfile)         // Customer's profile
        customerRoutes.POST("/tickets", createTicket)        // Customer support
    }
    
    // Staff manages customers - staff can access customer management
    staffManageCustomers := r.Group("/api/staff/customers")
    staffManageCustomers.Use(staffAuth.RequestValidator()) // Validates staff JWT
    {
        staffManageCustomers.GET("", listAllCustomers)       // Staff views all customers
        staffManageCustomers.GET("/:id", getCustomerDetail)  // Staff views customer detail
        staffManageCustomers.PUT("/:id", updateCustomer)     // Staff updates customer
    }
    
    // Staff manages vendors - staff can access vendor management
    staffManageVendors := r.Group("/api/staff/vendors")
    staffManageVendors.Use(staffAuth.RequestValidator()) // Validates staff JWT
    {
        staffManageVendors.GET("", listAllVendors)
        staffManageVendors.PUT("/:id/approve", approveVendor)
    }
    
    // Admin manages everything - admin has full access
    adminRoutes := r.Group("/api/admin")
    adminRoutes.Use(adminAuth.RequestValidator()) // Validates admin JWT
    {
        adminRoutes.GET("/users", getAllUsers)               // All users from all domains
        adminRoutes.GET("/staff", getAllStaff)               // Manage staff accounts
        adminRoutes.POST("/system/config", updateConfig)     // System configuration
    }
    
    log.Fatal(http.ListenAndServe(":8080", r))
}

func getMyOrders(c *gin.Context) { /* Customer's orders */ }
func getMyProfile(c *gin.Context) { /* Customer's profile */ }
func createTicket(c *gin.Context) { /* Support ticket */ }
func listAllCustomers(c *gin.Context) { /* Staff manages customers */ }
func getCustomerDetail(c *gin.Context) { /* Staff views customer */ }
func updateCustomer(c *gin.Context) { /* Staff updates customer */ }
func listAllVendors(c *gin.Context) { /* Staff manages vendors */ }
func approveVendor(c *gin.Context) { /* Staff approves vendor */ }
func getAllUsers(c *gin.Context) { /* Admin views all */ }
func getAllStaff(c *gin.Context) { /* Admin manages staff */ }
func updateConfig(c *gin.Context) { /* Admin config */ }
```

### RequestValidator - The Key to Cross-Service Access

The `RequestValidator()` method is the **core mechanism** for implementing flexible access control:

```go
// RequestValidator validates JWT tokens from a specific auth service
validator := authService.RequestValidator()
```

**How it works:**

1. **Customer routes protected by customer validator**:
   ```go
   customerRoutes.Use(customerAuth.RequestValidator())
   // ✅ Only customer JWT tokens are valid
   // ❌ Staff/Admin tokens are rejected
   ```

2. **Staff manages customers using staff validator**:
   ```go
   staffManageCustomers.Use(staffAuth.RequestValidator())
   // ✅ Only staff JWT tokens are valid
   // ✅ Staff can access customer management endpoints
   // ❌ Customer tokens are rejected (customers can't manage other customers)
   ```

3. **Admin has universal access**:
   ```go
   adminRoutes.Use(adminAuth.RequestValidator())
   // ✅ Only admin JWT tokens are valid
   // ✅ Admin can manage all services
   ```

**Real-world example:**

```
Customer Portal (customer.example.com):
  - Login: POST /customer/auth/signup      (no auth)
  - My Orders: GET /api/customer/orders    (customerAuth.RequestValidator())
  
Staff Dashboard (staff.example.com):
  - Login: POST /staff/auth/signin         (no auth)
  - Manage Customers: GET /api/staff/customers  (staffAuth.RequestValidator())
  - Manage Vendors: GET /api/staff/vendors      (staffAuth.RequestValidator())
  
Admin Panel (admin.example.com):
  - Login: POST /admin/auth/signin         (no auth)
  - System Config: POST /api/admin/config  (adminAuth.RequestValidator())
```

### Independent Configuration

Each service can have its own:
- **OAuth providers** (different Google/Facebook apps for different user types)
- **CAPTCHA settings** (stricter for public users, relaxed for staff)
- **SMS providers** (different Twilio accounts or AWS SNS configurations)
- **Security policies** (password requirements, MFA enforcement)
- **Email templates** (customized branding per user type)
- **Rate limits** (different limits for different user types)

All configurations are stored in the database and can be modified at runtime without code changes.

## Frontend Integration

Slauth provides official TypeScript and Vue.js packages for seamless frontend integration.

### TypeScript SDK

```bash
npm install @cybersailor/slauth-ts
```

#### Single-Tenant Frontend

```typescript
import { createClients } from '@cybersailor/slauth-ts'

// Create auth and admin clients
const { authClient, adminClient } = createClients({
  auth: { url: 'http://localhost:8080/auth' },
  admin: { url: 'http://localhost:8080/admin' },
  autoRefreshToken: true,
  persistSession: true,
})

// User authentication
const { data, error } = await authClient.signUp({
  email: 'user@example.com',
  password: 'Password123!'
})

// Admin operations
const users = await adminClient.listUsers()
```

#### Multi-Tenant Frontend

```typescript
import { createClients } from '@cybersailor/slauth-ts'

// Customer portal clients
const { authClient: customerAuth, adminClient: customerAdmin } = createClients({
  auth: { url: 'http://localhost:8080/customer/auth' },
  admin: { url: 'http://localhost:8080/customer/admin' },
  autoRefreshToken: true,
  persistSession: true,
})

// Vendor portal clients
const { authClient: vendorAuth, adminClient: vendorAdmin } = createClients({
  auth: { url: 'http://localhost:8080/vendor/auth' },
  admin: { url: 'http://localhost:8080/vendor/admin' },
  autoRefreshToken: true,
  persistSession: true,
})

// Staff portal clients (can manage customers and vendors)
const { authClient: staffAuth, adminClient: staffAdmin } = createClients({
  auth: { url: 'http://localhost:8080/staff/auth' },
  admin: { url: 'http://localhost:8080/staff/admin' },
  autoRefreshToken: true,
  persistSession: true,
})

// Staff can manage customer users
const customers = await staffAdmin.listUsers() // Lists customer users
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
    :providers="['google']"
  />
</template>

<script setup lang="ts">
import { createClients } from '@cybersailor/slauth-ts'
import { Auth } from '@cybersailor/slauth-ui-vue'
import '@cybersailor/slauth-ui-vue/style.css'

const { authClient, adminClient } = createClients({
  auth: { url: 'http://localhost:8080/auth' },
  admin: { url: 'http://localhost:8080/admin' },
  autoRefreshToken: true,
  persistSession: true,
})
</script>
```

#### Multi-Tenant Vue Example

```vue
<!-- CustomerPortal.vue -->
<template>
  <Auth
    :auth-client="customerAuth"
    appearance="default"
    :providers="['google']"
  />
</template>

<script setup lang="ts">
import { createClients } from '@cybersailor/slauth-ts'
import { Auth } from '@cybersailor/slauth-ui-vue'

const { authClient: customerAuth } = createClients({
  auth: { url: 'http://localhost:8080/customer/auth' },
  admin: { url: 'http://localhost:8080/customer/admin' },
})
</script>
```

```vue
<!-- VendorPortal.vue -->
<template>
  <Auth
    :auth-client="vendorAuth"
    appearance="default"
    :providers="['google']"
  />
</template>

<script setup lang="ts">
import { createClients } from '@cybersailor/slauth-ts'
import { Auth } from '@cybersailor/slauth-ui-vue'

const { authClient: vendorAuth } = createClients({
  auth: { url: 'http://localhost:8080/vendor/auth' },
  admin: { url: 'http://localhost:8080/vendor/admin' },
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

Slauth maintains comprehensive test coverage with both unit tests and E2E tests. Run the test suite:

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
| Multi-Tenant | ✅ Native | ❌ | ✅ (Paid) | ⚠️ Realms |
| Self-Hosted | ✅ | ✅ | Limited | ✅ |
| Custom Providers | ✅ | Limited | ❌ | ✅ |
| Independent Configs | ✅ Per Service | ❌ | ⚠️ Limited | ⚠️ Per Realm |
| License | Apache 2.0* | MIT | Proprietary | Apache 2.0 |
| Database | Any (GORM) | PostgreSQL | N/A | Multiple |
| Runtime Config | ✅ Database | ❌ Code Only | ⚠️ UI Only | ✅ |

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
