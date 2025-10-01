# Development Workflow Cheatsheet

## Quick Start Commands

### Terminal 1: Backend
```bash
make demo-backend
```
Auto-starts dev-services (Redis, MailHog, SMSHog) if not running.

### Terminal 2: Frontend
```bash
make demo-frontend
```
Auto-builds dependencies (slauth-ts, slauth-ui-vue) if needed.

### Terminal 3: E2E Tests
```bash
make dev-e2e
```
Requires backend on `:8080` and frontend on `:5180`.

## Service URLs

| Service | URL |
|---------|-----|
| Backend | http://localhost:8080 |
| Frontend | http://localhost:5180 |
| MailHog UI | http://localhost:18025 |
| SMSHog UI | http://localhost:18026 |
| Redis | localhost:16379 |
| Backend Logs | tail -f tmp/output.log |

## Development Infrastructure

### Start/Stop Dev Services
```bash
make dev-services         # Start Redis, MailHog, SMSHog
make dev-services-down    # Stop all dev services
```

### Hot Reload Configuration
- **Backend**: Air watches `pkg/`, `demo/src/` for `.go`, `.tmpl`, `.html`
- **Frontend**: Vite HMR for instant updates

## E2E Environment (Containerized)

```bash
make e2e-up      # Start E2E containers
make e2e-test    # Run E2E tests
make e2e-down    # Stop E2E containers
make e2e-full    # Complete cycle
```

### E2E URLs
- Frontend: http://localhost:15180
- Backend: http://localhost:18080
- PostgreSQL: localhost:15432

## Additional Commands

```bash
make all           # Build everything
make test          # Backend tests (SQLite)
make test-mysql    # Backend tests (MySQL)
make test-pgsql    # Backend tests (PostgreSQL)
make fmt           # Format code
make lint          # Run linter
```

## Troubleshooting

### Check Services
```bash
lsof -i :8080                                    # Backend port
curl http://localhost:8080/health                # Backend health
curl http://localhost:5180                       # Frontend
curl http://localhost:18025/api/v1/messages      # MailHog API
```

### Clean Build
```bash
# Frontend
cd packages/demo-fe
rm -rf node_modules dist
npm install

# Check logs
cat demo/src/build-errors.log    # Backend errors
tail -f tmp/output.log            # Backend runtime
```

## Files

### Configuration
- docker/docker-compose.dev-infra.yml - Dev services
- Makefile - Main commands
- tools/mk/dev.mk - Dev workflow
- tools/mk/e2e.mk - E2E workflow

### Demo Application
- demo/src/main.go - Backend entry
- packages/demo-fe/src/main.ts - Frontend entry
- packages/demo-fe/src/router/index.ts - Routes
- packages/demo-fe/src/views/AuthView.vue - Auth UI

### Core Backend
- pkg/ - Core packages
- pkg/controller/ - HTTP handlers
- pkg/services/ - Business logic
- pkg/models/ - Data models

### Frontend Packages
- packages/slauth-ts/ - TypeScript SDK
- packages/slauth-ui-vue/ - Vue UI components

## Reference Code

### Backend Entry
- demo/src/main.go:1-175 (Server setup)

### Frontend Entry
- packages/demo-fe/src/main.ts:1-50 (App initialization)
- packages/demo-fe/src/views/AuthView.vue:1-100 (Auth component usage)

### Configuration Examples
- docker/docker-compose.dev-infra.yml:1-50 (Dev services config)

## Test Cases

### Backend Tests
- tests/01-signup-and-user-queries_test.go
- tests/02-otp-verification_test.go
- tests/03-signin-authentication_test.go
- tests/05-session-management_test.go
- tests/09-mfa-authentication_test.go

### E2E Tests
- packages/demo-fe/e2e/01-complete-signup-flow.spec.ts
- packages/demo-fe/e2e/02-email-signin-flow.spec.ts
- packages/demo-fe/e2e/03-otp-verification-flow.spec.ts
- packages/demo-fe/e2e/05-form-validation.spec.ts
- packages/demo-fe/e2e/06-token-refresh-flow.spec.ts

## Search Keywords

### Makefile Targets
- `^demo-backend:` - Backend startup target
- `^demo-frontend:` - Frontend startup target
- `^dev-e2e:` - E2E test target
- `^dev-services:` - Dev services target

### Development Scripts
- `air\.toml` - Air hot reload config
- `vite\.config` - Vite configuration
- `playwright\.config` - Playwright E2E config

### Service Ports
- `:8080` - Backend server port
- `:5180` - Frontend dev server port
- `:15180` - Frontend E2E container port
- `:18025` - MailHog web UI
- `:18026` - SMSHog web UI
- `:16379` - Redis port

### Log Files
- `tmp/output\.log` - Backend runtime logs
- `demo/src/build-errors\.log` - Backend build errors

## Execution Order

1. Start dev-services (auto-started by demo-backend)
2. Start backend (`make demo-backend`)
3. Start frontend (`make demo-frontend`)
4. Run E2E tests (`make dev-e2e`)
5. Monitor logs (`tail -f tmp/output.log`)
6. Stop services (`make dev-services-down`)

## Notes

- Backend uses SQLite in-memory (data lost on restart)
- E2E tests use real MailHog for email verification
- Hot reload preserves most development state
- Always start backend before frontend

