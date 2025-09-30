# Security Policy

## Supported Versions

We take security seriously and actively maintain the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Slauth, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email us directly at:

**developer@cybersailor.ai**

### What to Include

Please include the following information in your report:

1. **Description** - A clear description of the vulnerability
2. **Impact** - What can an attacker do with this vulnerability?
3. **Reproduction Steps** - Detailed steps to reproduce the issue
4. **Affected Versions** - Which versions are affected?
5. **Suggested Fix** - If you have ideas on how to fix it (optional)
6. **Your Contact Info** - So we can follow up with you

### Example Report

```
Subject: [SECURITY] JWT Token Bypass Vulnerability

Description:
A vulnerability in the JWT validation logic allows...

Impact:
An attacker could bypass authentication by...

Steps to Reproduce:
1. Create a malformed JWT token with...
2. Send request to /api/protected endpoint
3. Observe that authentication is bypassed

Affected Versions:
0.8.0

Environment:
- Go version: 1.21
- Database: PostgreSQL 14
- OS: Linux

Suggested Fix:
Add additional validation in pkg/services/jwt_service.go...
```

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Fix Development**: Depends on severity and complexity
- **Public Disclosure**: After fix is released and users have time to update

## Security Update Process

When a security issue is confirmed:

1. We will acknowledge receipt of your report
2. We will assess the severity and impact
3. We will develop a fix
4. We will test the fix thoroughly
5. We will prepare a security advisory
6. We will release a patched version
7. We will publish the security advisory

## Severity Levels

We classify vulnerabilities using the following severity levels:

### Critical
- Remote code execution
- Authentication bypass
- SQL injection
- Privilege escalation

### High
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Information disclosure of sensitive data
- Denial of service

### Medium
- Information disclosure of non-sensitive data
- Session fixation
- Missing security headers

### Low
- Best practice violations
- Minor information leaks

## Security Best Practices

### For Developers Using Slauth

1. **Keep Updated**
   - Always use the latest stable version
   - Subscribe to security advisories
   - Review CHANGELOG.md for security fixes

2. **Secure Configuration**
   - Use strong JWT secrets (minimum 32 characters)
   - Enable rate limiting
   - Configure appropriate session timeouts
   - Use HTTPS in production
   - Set secure CORS policies

3. **Database Security**
   - Use encrypted database connections
   - Follow principle of least privilege for DB users
   - Regularly backup your database
   - Keep database software updated

4. **Secret Management**
   - Never commit secrets to version control
   - Use environment variables or secret managers
   - Rotate secrets regularly
   - Use different secrets for different environments

5. **Monitoring**
   - Monitor authentication failures
   - Set up alerts for suspicious activity
   - Log security-relevant events
   - Regularly review logs

### For Contributors

1. **Code Review**
   - All code changes require review
   - Security-sensitive changes require extra scrutiny
   - Use static analysis tools

2. **Testing**
   - Write tests for security features
   - Test edge cases and error conditions
   - Maintain 100% test coverage for critical paths

3. **Dependencies**
   - Keep dependencies updated
   - Review dependency security advisories
   - Minimize dependency count
   - Audit new dependencies

## Security Features

Slauth includes the following security features by default:

- **Password Security**
  - Bcrypt hashing with configurable cost
  - Password strength validation
  - Password history (optional)
  - Breach detection integration (optional)

- **Session Security**
  - Secure token generation
  - Token expiration
  - Refresh token rotation
  - Session invalidation

- **Rate Limiting**
  - Per-endpoint rate limits
  - IP-based limiting
  - Configurable thresholds

- **Input Validation**
  - Request validation
  - SQL injection prevention (via GORM)
  - XSS prevention

- **Audit Logging**
  - Authentication events
  - Failed login attempts
  - Password changes
  - Admin actions

## Disclosure Policy

We follow a coordinated disclosure process:

1. **Private Disclosure**: Security researchers report issues privately
2. **Fix Development**: We develop and test a fix
3. **User Notification**: We notify users via security advisory
4. **Public Disclosure**: After users have time to update (typically 7-14 days)

## Security Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

- Your name could be here!

## Contact

For security-related questions or concerns:

- **Email**: developer@cybersailor.ai
- **Security Advisories**: https://github.com/thecybersailor/slauth/security/advisories

For general questions, please use GitHub Issues or Discussions.

## Legal

This security policy is subject to change without notice. By using Slauth, you agree to follow responsible disclosure practices when reporting security vulnerabilities.

---

Last Updated: 2025-09-30
