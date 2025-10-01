# Development Workflow

## Overview

This document describes the standard Test-Driven Development (TDD) workflow for the Slauth project.

## Prerequisites

- Go 1.23+
- Node.js 18+
- Docker and Docker Compose
- Make
- Air (Go hot reload tool)

## Development Workflow

### 1. Start Backend with Infrastructure

```bash
make demo-backend
```

This command will:
- **Auto-check** if dev-services (Redis, MailHog, SMSHog) are running
- **Auto-start** dev-services if not running
- Start the backend server with **hot reload** enabled
- Monitor changes in `pkg/` and `demo/src/` directories

**Backend Configuration:**
- Server: `http://localhost:8080`
- Database: SQLite in-memory
- Redis: `localhost:16379`
- SMTP: `localhost:11025` (MailHog)
- SMS: `http://localhost:18026` (SMSHog)

**View Backend Logs:**
```bash
tail -f tmp/output.log
```

### 2. Start Frontend

```bash
make demo-frontend
```

This command will:
- **Auto-check** if dependencies are built
- **Auto-build** if needed (slauth-ts and slauth-ui-vue packages)
- Install npm dependencies
- Start Vite dev server with **hot reload**

**Frontend URLs:**
- Dev Server: `http://localhost:5173` or `http://localhost:5174`

### 3. Run E2E Tests

```bash
make dev-e2e
```

This command will:
- **Auto-check** if backend and frontend are running
- Run Playwright E2E tests against local development environment
- Tests run in headless mode by default

**Requirements:**
- Backend must be running on `http://localhost:8080`
- Frontend must be running on `http://localhost:5173` or `:5174`

## Supporting Services

### MailHog (Email Testing)
- Web UI: `http://localhost:18025`
- SMTP: `localhost:11025`
- View all sent emails in the web interface

### SMSHog (SMS Testing)  
- Web UI: `http://localhost:18026`
- View all sent SMS messages

### Redis
- Address: `localhost:16379`

### Manage Dev Services

**Start services manually:**
```bash
make dev-services
```

**Stop services:**
```bash
make dev-services-down
```

## Hot Reload Features

### Backend Hot Reload
- Powered by **Air**
- Watches: `pkg/`, `demo/src/`
- File types: `.go`, `.tmpl`, `.html`
- Auto-rebuild on file changes
- Logs: `tmp/output.log` and `demo/src/build-errors.log`

### Frontend Hot Reload
- Powered by **Vite HMR**
- Instant updates on file changes
- Preserves component state when possible

## Complete TDD Workflow

### Terminal 1: Backend
```bash
make demo-backend
```

### Terminal 2: Frontend
```bash
make demo-frontend
```

### Terminal 3: Watch Logs (Optional)
```bash
tail -f tmp/output.log
```

### Terminal 4: Run Tests
```bash
make dev-e2e
```

## Directory Structure

```
slauth/
├── demo/src/          # Demo backend application
├── packages/
│   ├── demo-fe/       # Demo frontend application
│   │   └── e2e/       # E2E test suites
│   ├── slauth-ts/     # TypeScript SDK
│   └── slauth-ui-vue/ # Vue UI components
├── pkg/               # Core backend packages
├── tmp/
│   └── output.log     # Backend runtime logs
└── docker/            # Docker configuration
    └── docker-compose.dev-infra.yml
```

## Troubleshooting

### Backend won't start
```bash
# Check if ports are occupied
lsof -i :8080

# Restart dev services
make dev-services-down
make dev-services
```

### Frontend won't start
```bash
# Clean and rebuild
cd packages/demo-fe
rm -rf node_modules dist
npm install
```

### E2E tests fail
```bash
# Verify services are running
curl http://localhost:8080/health
curl http://localhost:5173

# Check MailHog
curl http://localhost:18025/api/v1/messages
```

### View build errors
```bash
# Backend build errors
cat demo/src/build-errors.log

# Frontend build errors (shown in terminal)
```

## Additional Commands

### Build Everything
```bash
make all
```

### Run Backend Tests
```bash
make test           # SQLite (default)
make test-mysql     # MySQL
make test-pgsql     # PostgreSQL
```

### Format Code
```bash
make fmt
```

### Run Linter
```bash
make lint
```

## E2E Testing Environment

For full E2E testing with containerized services:

```bash
# Start full E2E environment
make e2e-up

# Run E2E tests
make e2e-test

# Stop E2E environment
make e2e-down

# Or run complete cycle
make e2e-full
```

**E2E Environment:**
- Frontend: `http://localhost:15180`
- Backend: `http://localhost:18080`
- PostgreSQL: `localhost:15432`
- Redis: `localhost:16379`
- MailHog: `http://localhost:18025`
- SMSHog: `http://localhost:18026`

## Best Practices

1. **Always start backend first** - Frontend may depend on backend APIs
2. **Monitor logs** - Keep `tmp/output.log` open in a separate terminal
3. **Check MailHog** - Verify email delivery during development
4. **Run E2E tests frequently** - Catch integration issues early
5. **Stop services when done** - `make dev-services-down` to clean up

## Quick Reference

| Command | Description |
|---------|-------------|
| `make demo-backend` | Start backend with hot reload |
| `make demo-frontend` | Start frontend with hot reload |
| `make dev-e2e` | Run E2E tests against local dev |
| `make dev-services` | Start Redis, MailHog, SMSHog |
| `make dev-services-down` | Stop dev services |
| `make e2e-full` | Full E2E test cycle (Docker) |
| `tail -f tmp/output.log` | View backend logs |

## Notes

- Backend uses SQLite in-memory for fast development
- All data is lost when backend restarts
- MailHog and SMSHog provide UI for inspecting sent messages
- Hot reload preserves most development state
- E2E tests use real MailHog for email verification

