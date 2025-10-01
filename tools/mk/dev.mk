# Development tools

.PHONY: fmt lint lint-install install-hooks demo-backend demo-frontend dev-services dev-services-down dev-e2e

# Format Go code with gofmt -s
fmt:
	@echo "Formatting Go code..."
	@gofmt -s -w $(GO_FILES)
	@echo "Go code formatted successfully!"

# Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run ./...
	@echo "Linting completed!"

# Install golangci-lint
lint-install:
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "golangci-lint installed successfully!"

# Install Git hooks for test verification
install-hooks:
	@echo "Installing Git hooks..."
	@bash tools/install-hooks.sh
	@echo "Git hooks installed successfully!"

# Run demo backend with hot reload (using dev-services)
demo-backend:
	@echo "Checking dev-services status..."
	@if ! docker-compose -f docker/docker-compose.dev-infra.yml ps redis | grep -q "Up"; then \
		echo "Redis is not running. Starting dev-services..."; \
		$(MAKE) dev-services; \
	else \
		echo "Dev-services are already running."; \
	fi
	@echo "Starting demo backend with hot reload..."
	@mkdir -p demo/src/tmp
	@mkdir -p tmp
	@SYS_REDIS_ADDR=localhost:16379 \
		SYS_SMTP_HOST=localhost \
		SYS_SMTP_PORT=11025 \
		SYS_SMTP_FROM=dev@slauth.local \
		SYS_SMTP_FROM_NAME="Slauth Dev" \
		AWS_SNS_ENDPOINT=http://localhost:18026 \
		air \
			--root . \
			--build.cmd "cd demo/src && go build -o ./tmp/main ." \
			--build.bin "demo/src/tmp/main -c demo/src/.env | tee tmp/output.log" \
			--build.include_dir "pkg,demo/src" \
			--build.include_ext "go,tpl,tmpl,html" \
			--build.exclude_dir "assets,tmp,vendor,testdata" \
			--build.exclude_regex "_test.go" \
			--build.delay 1000 \
			--tmp_dir "demo/src/tmp" \
			--build.log "demo/src/build-errors.log"

# Run demo frontend with hot reload
demo-frontend:
	@echo "Checking if frontend dependencies are built..."
	@if [ ! -d "packages/slauth-ts/dist" ] || [ ! -d "packages/slauth-ui-vue/dist" ]; then \
		echo "Building dependencies..."; \
		$(MAKE) all; \
	fi
	@echo "Starting demo frontend with hot reload..."
	@cd packages/demo-fe && npm i && npm run dev

# Start development support services (Redis, MailHog, SMSHog)
dev-services:
	@echo "Starting development support services..."
	@docker-compose -f docker/docker-compose.dev-infra.yml up -d redis mailhog smshog
	@echo "Development services ready!"
	@echo "Redis:   localhost:16379"
	@echo "MailHog: http://localhost:18025"
	@echo "SMSHog:  http://localhost:18026"

# Stop development support services
dev-services-down:
	@echo "Stopping development support services..."
	@docker-compose -f docker/docker-compose.dev-infra.yml stop redis mailhog smshog
	@docker-compose -f docker/docker-compose.dev-infra.yml rm -f redis mailhog smshog
	@echo "Development services stopped!"

# Run E2E tests against local development environment
dev-e2e:
	@echo "Running E2E tests against local development..."
	@echo "Make sure demo-backend and demo-frontend are running!"
	@echo ""
	@if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then \
		echo "Error: Backend is not running at http://localhost:8080"; \
		echo "Please run 'make demo-backend' in another terminal first."; \
		exit 1; \
	fi
	@if ! curl -s http://localhost:5173 > /dev/null 2>&1 && ! curl -s http://localhost:5174 > /dev/null 2>&1; then \
		echo "Error: Frontend is not running at http://localhost:5173 or :5174"; \
		echo "Please run 'make demo-frontend' in another terminal first."; \
		exit 1; \
	fi
	@echo "Backend and frontend are running. Starting E2E tests..."
	@cd packages/demo-fe && npm run test:e2e
