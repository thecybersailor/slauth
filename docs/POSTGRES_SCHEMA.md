# PostgreSQL Schema Support

## Overview

slauth supports custom schema in PostgreSQL, primarily used to **avoid table name conflicts**.

## Core Understanding

### slauth Uses Main Project's Database Connection

```go
// Main project code
db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})

// slauth uses the same db connection
userAuth := registry.RegisterAuthService("user", jwtSecret, appSecret, db)
```

**Key Points:**
- slauth and the main project share the same `*gorm.DB` connection
- Not separate databases, but different schemas in the same database
- **Main project can directly access slauth's tables** (via full table name `schema.table`)

## Schema Purpose

### Resolving Table Name Conflicts

**Problem Scenario:**
```
Main project and slauth both have users table
public.users        ← Main project's user table (business users)
public.users        ← slauth's user table (auth users) CONFLICT!
```

**Solution:**
```
public.users        ← Main project's user table
slauth_schema.users ← slauth's user table, namespace separation
```

## Configuration

### 1. Test Environment Configuration

```bash
# tests/pgsql-custom-schema.conf
SYS_DB_TYPE=postgres
POSTGRES_HOST=localhost
POSTGRES_USER=postgres
POSTGRES_DBNAME=myapp_db
POSTGRES_PASSWORD=postgres
POSTGRES_PORT=5432
POSTGRES_SCHEMA=slauth_schema
```

### 2. Production Environment Configuration

```go
// Main project initializes database
db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})

// Configure slauth to use custom schema
os.Setenv("POSTGRES_SCHEMA", "slauth_schema")

// Register slauth (tables will be created in slauth_schema)
authService := registry.RegisterAuthService("user", jwtSecret, appSecret, db)
```

## Cross-Schema Queries

Since they use the same database connection, the main project can directly access slauth's data.

### Example: Query User Orders and Authentication Info

```go
type OrderWithAuth struct {
    OrderID     int
    Amount      float64
    UserEmail   string
    AuthUserID  string
    LastSignIn  *time.Time
}

var results []OrderWithAuth
db.Raw(`
    SELECT 
        o.id as order_id,
        o.amount,
        o.user_email,
        u.id as auth_user_id,
        u.last_sign_in_at
    FROM public.orders o
    LEFT JOIN slauth_schema.users u ON o.user_email = u.email
    WHERE o.created_at > ?
`, time.Now().AddDate(0, -1, 0)).Scan(&results)
```

### Example: User Login Statistics

```go
// Main project queries auth data to generate reports
var loginStats struct {
    TotalUsers      int
    ActiveToday     int
    NeverLoggedIn   int
}

db.Raw(`
    SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN last_sign_in_at::date = CURRENT_DATE THEN 1 END) as active_today,
        COUNT(CASE WHEN last_sign_in_at IS NULL THEN 1 END) as never_logged_in
    FROM slauth_schema.users
    WHERE instance_id = ?
`, instanceID).Scan(&loginStats)
```

## Real-World Use Cases

### 1. Associating Business Data with Users

Main project's business tables associate with slauth users via email:

```sql
-- Main project: orders table
CREATE TABLE public.orders (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255),
    amount DECIMAL
);

-- slauth: users table (in slauth_schema)
-- users table is automatically created in slauth_schema.users

-- Query orders and user authentication info
SELECT o.*, u.last_sign_in_at, u.email_confirmed_at
FROM public.orders o
JOIN slauth_schema.users u ON o.user_email = u.email;
```

### 2. Audit and Monitoring

```sql
-- Query users registered today with confirmed email
SELECT email, created_at, email_confirmed_at
FROM slauth_schema.users
WHERE created_at::date = CURRENT_DATE 
  AND email_confirmed_at IS NOT NULL;

-- Statistics on session data
SELECT 
    DATE(created_at) as date,
    COUNT(*) as session_count
FROM slauth_schema.sessions
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY DATE(created_at);
```

### 3. Data Cleanup and Maintenance

```sql
-- Clean up expired sessions
DELETE FROM slauth_schema.sessions
WHERE NOT_AFTER < NOW() - INTERVAL '30 days';

-- Find users who haven't logged in for a long time
SELECT id, email, last_sign_in_at
FROM slauth_schema.users
WHERE last_sign_in_at < NOW() - INTERVAL '1 year'
   OR last_sign_in_at IS NULL;
```

## Test Verification

### Test Files

1. **24-postgres-custom-schema_test.go**: Verifies schema configuration functionality
2. **25-schema-isolation_test.go**: Verifies namespace separation and cross-schema queries
3. **26-cross-schema-query_test.go**: Verifies cross-schema JOIN functionality

### Running Tests

```bash
cd tests
CONF_FILE=pgsql-custom-schema.conf go test -v -run TestSchemaIsolationTestSuite
```

### Test Coverage

- ✅ Schema automatically created
- ✅ Tables created in specified schema
- ✅ slauth functionality works normally (signup, login, session management)
- ✅ Can create main project tables in public schema
- ✅ Can query data across schemas

## Implementation Principle

Uses GORM's `NamingStrategy` to add schema prefix to table names:

```go
type PostgresSchemaNameStrategy struct {
    schema.NamingStrategy
    Schema string
}

func (ps *PostgresSchemaNameStrategy) TableName(table string) string {
    tableName := ps.NamingStrategy.TableName(table)
    if ps.Schema != "" {
        return ps.Schema + "." + tableName
    }
    return tableName
}
```

All GORM operations automatically use full table names:
```sql
-- Automatic conversion
INSERT INTO users ... 
→ INSERT INTO slauth_schema.users ...

SELECT * FROM sessions WHERE ...
→ SELECT * FROM slauth_schema.sessions WHERE ...
```

## Permission Configuration Recommendations

### Development Environment

```sql
-- Use superuser for convenience in development
POSTGRES_USER=postgres
```

### Production Environment

```sql
-- Create dedicated user
CREATE USER myapp_user WITH PASSWORD 'secure_password';

-- Create schema
CREATE SCHEMA slauth_schema;

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA slauth_schema TO myapp_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA slauth_schema TO myapp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA slauth_schema TO myapp_user;

-- Set default privileges (auto-grant for new tables)
ALTER DEFAULT PRIVILEGES IN SCHEMA slauth_schema 
GRANT ALL ON TABLES TO myapp_user;
```

## Notes

1. **Optional Configuration**: If `POSTGRES_SCHEMA` is not configured, all tables are created in `public` schema (default behavior)

2. **PostgreSQL Only**: This feature only supports PostgreSQL, MySQL and SQLite ignore this configuration

3. **Naming Convention**: Recommend using lowercase with underscores for schema names, e.g., `slauth_schema`, `auth_schema`

4. **Migration Note**: To migrate from public schema to custom schema:
   ```sql
   ALTER TABLE public.users SET SCHEMA slauth_schema;
   ```

5. **Performance Impact**: Using schema prefix has negligible performance impact

## Summary

- **Schema is not isolation**: It's a namespace to avoid table name conflicts
- **Shared connection**: slauth and main project use the same database connection
- **JOIN possible**: Main project can freely access slauth's tables
- **Production recommended**: Use custom schema for clearer database structure

