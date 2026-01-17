# User Lifecycle Hooks

Slauth provides a user lifecycle hooks system that allows you to execute custom logic at key events such as user creation, authentication, session creation, and identity linking.

## Overview

Lifecycle hooks are a middleware system that uniformly triggers corresponding hooks regardless of which entry point creates the user (Signup, OAuth, Admin API). This allows you to handle post-creation business logic at a unified level, for example:

- Automatically create associated business system user records
- Sync user data to external systems
- Send welcome emails or notifications
- Record audit logs
- Initialize user configuration

## Available Hooks

### 1. BeforeUserCreatedUse

Triggered **before** user creation, allowing you to modify user data.

**Use Cases:**
- Modify `UserMetadata` or `AppMetadata` based on business rules
- Validate user creation conditions
- Set default values

**Note:** If the hook returns an error, the user creation transaction will roll back and the user will not be created.

### 2. AfterUserCreatedUse

Triggered **after** user creation, when the user has been saved to the database and assigned an ID.

**Use Cases:**
- Create associated business system user records (e.g., `platform_users` table)
- Send welcome emails
- Initialize user configuration
- Sync to external systems

**Note:** If the hook returns an error, the user creation transaction will roll back and the created user will be deleted.

### 3. AuthenticatedUse

Triggered after successful user authentication (regardless of method: password, OAuth, Magic Link, etc.).

**Use Cases:**
- Update last login time
- Record login logs
- Send login notifications
- Check account status

### 4. SessionCreatedUse

Triggered when a session is created.

**Use Cases:**
- Record session creation logs
- Limit concurrent session count
- Send new device login notifications

### 5. IdentityLinkedUse

Triggered when an OAuth Identity is linked to a user.

**Use Cases:**
- Record OAuth linking logs
- Sync OAuth user information
- Update user profile information such as avatars

## Usage

### Basic Example

```go
package main

import (
    "log/slog"
    "github.com/thecybersailor/slauth/pkg/services"
    "gorm.io/gorm"
)

func InitSlauth(authService services.AuthService, mainDB *gorm.DB) error {
    // Register after user creation hook - automatically create platform_users
    authService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
        user := ctx.User()
        source := ctx.Source()
        
        slog.Info("User created hook triggered",
            "userID", user.ID,
            "source", source,
            "provider", ctx.Provider())
        
        // Create associated business system user
        platformUser := &PlatformUser{
            SlauthUserID: user.ID,
            Email:        user.GetModel().Email,
            CreatedAt:    time.Now(),
        }
        
        if err := mainDB.Create(platformUser).Error; err != nil {
            slog.Error("Failed to create platform user", "error", err)
            return err // Returning error will rollback the entire user creation transaction
        }
        
        return next()
    })
    
    // Register authentication success hook - update last login time
    authService.AuthenticatedUse(func(ctx services.AuthenticatedContext, next func() error) error {
        user := ctx.User()
        method := ctx.Method()
        
        slog.Info("User authenticated",
            "userID", user.ID,
            "method", method,
            "provider", ctx.Provider())
        
        // Update business system's last login time
        if err := mainDB.Model(&PlatformUser{}).
            Where("slauth_user_id = ?", user.ID).
            Update("last_login_at", time.Now()).Error; err != nil {
            slog.Error("Failed to update last login time", "error", err)
            // Don't return error to avoid affecting authentication flow
        }
        
        return next()
    })
    
    return nil
}
```

### Before Hook Modifying User Data

```go
authService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
    // Get current metadata
    metadata := ctx.UserMetadata()
    if metadata == nil {
        metadata = make(map[string]any)
    }
    
    // Modify metadata based on business rules
    metadata["account_type"] = "premium"
    metadata["trial_days"] = 30
    
    // Set modified metadata
    ctx.SetUserMetadata(metadata)
    
    return next()
})
```

### Execute Different Logic Based on Creation Source

```go
authService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
    user := ctx.User()
    source := ctx.Source()
    
    switch source {
    case services.UserCreatedSourceSignup:
        // Signup user: send welcome email
        sendWelcomeEmail(user)
        
    case services.UserCreatedSourceOAuth:
        // OAuth user: sync OAuth information
        provider := ctx.Provider()
        identity := ctx.Identity()
        syncOAuthInfo(user, provider, identity)
        
    case services.UserCreatedSourceAdmin:
        // Admin created: log admin action
        logAdminAction(user)
    }
    
    return next()
})
```

### Multiple Hooks Chained Execution

```go
// Hooks execute in registration order
authService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
    log.Println("Before hook 1")
    return next()
})

authService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
    log.Println("Before hook 2")
    return next()
})

authService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
    log.Println("After hook 1")
    return next()
})

// Execution order: Before hook 1 -> Before hook 2 -> Create user -> After hook 1
```

### Error Handling

```go
authService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
    user := ctx.User()
    
    // Check business rules
    if !isAllowedToCreateUser(user) {
        return services.NewError("business_rule_violation", "User creation not allowed")
    }
    
    // Create related record
    if err := createRelatedRecord(user); err != nil {
        // Returning error will cause transaction rollback, user will not be created
        return err
    }
    
    return next()
})
```

## Context Interface Reference

### UserCreatedContext

```go
type UserCreatedContext interface {
    FlowInterface
    User() *User                     // User object (ID=0 in Before, ID assigned in After)
    Source() UserCreatedSource       // Creation source: signup/oauth/admin/invite/magic_link
    Provider() string                // OAuth provider (OAuth scenarios only)
    Identity() *models.Identity      // OAuth identity (OAuth scenarios only)
    Response() *UserCreatedResponse
    
    // For Before hook to modify user data
    UserMetadata() map[string]any
    SetUserMetadata(map[string]any)
}
```

### AuthenticatedContext

```go
type AuthenticatedContext interface {
    FlowInterface
    User() *User
    Method() AuthMethod              // password/oauth/magic_link/otp
    Provider() string                // OAuth/MFA provider name
    Response() *AuthenticatedResponse
}
```

### SessionCreatedContext

```go
type SessionCreatedContext interface {
    FlowInterface
    User() *User
    Session() *Session
    Response() *SessionCreatedResponse
}
```

### IdentityLinkedContext

```go
type IdentityLinkedContext interface {
    FlowInterface
    User() *User
    Provider() string
    Identity() *models.Identity
    IsNewIdentity() bool             // true=newly created, false=already exists
    Response() *IdentityLinkedResponse
}
```

## User Creation Source (UserCreatedSource)

- `UserCreatedSourceSignup` - Created via Signup API
- `UserCreatedSourceOAuth` - Created via OAuth login
- `UserCreatedSourceAdmin` - Created via Admin API
- `UserCreatedSourceInvite` - Created via invitation
- `UserCreatedSourceMagicLink` - Created via Magic Link

## Authentication Method (AuthMethod)

- `AuthMethodPassword` - Password login
- `AuthMethodOAuth` - OAuth login
- `AuthMethodMagicLink` - Magic Link login
- `AuthMethodOTP` - OTP verification login

## Transaction Safety

All hooks execute within database transactions:

- **BeforeUserCreatedUse**: Executes in user creation transaction, returning error will rollback
- **AfterUserCreatedUse**: Executes in user creation transaction, returning error will rollback and delete the created user
- **AuthenticatedUse**: Not in transaction (authentication already completed), errors won't affect authentication result
- **SessionCreatedUse**: Not in transaction (session already created), errors won't affect session creation
- **IdentityLinkedUse**: Not in transaction (identity already created), errors won't affect identity linking

## Best Practices

1. **Create related records in AfterUserCreatedUse**: At this point the user ID is assigned, allowing safe creation of foreign key relationships

2. **Handle errors carefully**:
   - Before/After hook errors will cause user creation to fail
   - Other hook errors should not affect the main flow

3. **Avoid time-consuming operations in hooks**: Hooks execute in the request processing path and should remain fast

4. **Use logging**: Record key operations in hooks for debugging and auditing

5. **Consider idempotency**: Ensure hook logic is idempotent to avoid issues from repeated execution

## Complete Example

```go
package main

import (
    "context"
    "log/slog"
    "time"
    
    "github.com/thecybersailor/slauth/pkg/services"
    "gorm.io/gorm"
)

type PlatformUser struct {
    ID           uint      `gorm:"primaryKey"`
    SlauthUserID string    `gorm:"uniqueIndex;not null"`
    Email        *string   `gorm:"uniqueIndex"`
    AccountType  string    `gorm:"default:free"`
    LastLoginAt  *time.Time
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

func SetupLifecycleHooks(authService services.AuthService, db *gorm.DB) {
    // Before hook: set default metadata
    authService.BeforeUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
        metadata := ctx.UserMetadata()
        if metadata == nil {
            metadata = make(map[string]any)
        }
        metadata["account_type"] = "free"
        metadata["trial_ends_at"] = time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
        ctx.SetUserMetadata(metadata)
        return next()
    })
    
    // After hook: create platform_users record
    authService.AfterUserCreatedUse(func(ctx services.UserCreatedContext, next func() error) error {
        user := ctx.User()
        
        platformUser := &PlatformUser{
            SlauthUserID: user.ID,
            Email:        user.GetModel().Email,
            AccountType:  "free",
            CreatedAt:    time.Now(),
            UpdatedAt:    time.Now(),
        }
        
        if err := db.Create(platformUser).Error; err != nil {
            slog.Error("Failed to create platform user", 
                "error", err, 
                "slauth_user_id", user.ID)
            return err
        }
        
        slog.Info("Platform user created",
            "slauth_user_id", user.ID,
            "source", ctx.Source())
        
        return next()
    })
    
    // Authenticated hook: update last login time
    authService.AuthenticatedUse(func(ctx services.AuthenticatedContext, next func() error) error {
        user := ctx.User()
        now := time.Now()
        
        if err := db.Model(&PlatformUser{}).
            Where("slauth_user_id = ?", user.ID).
            Update("last_login_at", now).Error; err != nil {
            slog.Error("Failed to update last login time", "error", err)
            // Don't return error to avoid affecting authentication flow
        }
        
        slog.Info("User authenticated",
            "user_id", user.ID,
            "method", ctx.Method(),
            "provider", ctx.Provider())
        
        return next()
    })
    
    // SessionCreated hook: record session creation
    authService.SessionCreatedUse(func(ctx services.SessionCreatedContext, next func() error) error {
        user := ctx.User()
        session := ctx.Session()
        
        slog.Info("Session created",
            "user_id", user.ID,
            "session_id", session.HashID)
        
        return next()
    })
    
    // IdentityLinked hook: record OAuth linking
    authService.IdentityLinkedUse(func(ctx services.IdentityLinkedContext, next func() error) error {
        user := ctx.User()
        provider := ctx.Provider()
        identity := ctx.Identity()
        
        slog.Info("Identity linked",
            "user_id", user.ID,
            "provider", provider,
            "is_new", ctx.IsNewIdentity(),
            "identity_id", identity.ID)
        
        return next()
    })
}
```

## Testing

Refer to test files to understand how to test hooks:

- `tests/33-user-lifecycle-hooks_test.go` - User creation hooks tests
- `tests/34-authenticated-hooks_test.go` - Authentication hooks tests
- `tests/35-session-hooks_test.go` - Session hooks tests

## Notes

1. **Backward Compatibility**: Existing middleware like `SignupUse`, `SigninUse` are unaffected and continue to work

2. **Optional**: If the project doesn't register middleware, behavior remains exactly the same with no performance overhead

3. **Flexibility**: Before hooks can modify data, After hooks can create related records

4. **Transaction Safety**: All hooks execute within transactions, errors automatically rollback

5. **Performance**: Only executes when middleware is registered, no performance overhead
