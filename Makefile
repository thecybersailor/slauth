# slauth Build System

.PHONY: all build-ts-sdk build-vue-ui help docs-install generate-schemas test generate-templates clean clean-schemas regen-schemas fmt lint lint-install
.DEFAULT_GOAL := all

# Go source files
GO_FILES := $(shell find . -name "*.go" -not -path "./vendor/*")

# Default target
all: generate-templates generate-schemas build-ts-sdk build-vue-ui

# Generate templates from templates/ directory
generate-templates: pkg/consts/tmpl.go

# Template generation
pkg/consts/tmpl.go: $(shell find templates -name "*.tmpl")
	@echo "Generating templates..."
	@python3 tools/generate_templates.py
	@echo "Templates generated successfully!"

# Build TypeScript SDK (depends on types and documentation)
build-ts-sdk: packages/slauth-ts/dist/cjs/index.js

# TypeScript SDK build depends on generated types and schemas
packages/slauth-ts/dist/cjs/index.js: packages/slauth-ts/src/types/auth-api.ts packages/slauth-ts/src/types/admin-api.ts packages/slauth-ts/src/schemas/auth-api.schemas.ts packages/slauth-ts/src/schemas/admin-api.schemas.ts
	@echo "Building TypeScript SDK..."
	@cd packages/slauth-ts && npm run build
	@echo "TypeScript SDK built successfully!"

# Build Vue UI library
build-vue-ui: packages/slauth-ui-vue/dist/index.es.js

# Vue UI library build
packages/slauth-ui-vue/dist/index.es.js: $(shell find packages/slauth-ui-vue/src -type f -name "*.ts" -o -name "*.vue" -o -name "*.js")
	@echo "Building Vue UI library..."
	@cd packages/slauth-ui-vue && npm run build
	@echo "Vue UI library built successfully!"

# Generated types depend on API documentation
packages/slauth-ts/src/types/auth-api.ts packages/slauth-ts/src/types/admin-api.ts: docs/specs/auth-api.json docs/specs/admin-api.json
	@echo "Generating optimized TypeScript types..."
	@cd packages/slauth-ts && npm run generate-types
	@echo "Optimized TypeScript types generated successfully!"

# Auth API documentation
docs/specs/auth-api.json: tools/prog/main.go $(GO_FILES)
	@echo "Generating Auth API documentation..."
	@mkdir -p docs/specs
	swag init -g tools/prog/main.go -o docs/temp/auth --parseDependency --parseInternal --parseDepth 1 --tags Auth
	@mv docs/temp/auth/swagger.json docs/specs/auth-api.json
	@rm -rf docs/temp/auth
	@echo "Auth API documentation generated: docs/specs/auth-api.json"

# Admin API documentation  
docs/specs/admin-api.json: tools/prog/main.go $(GO_FILES)
	@echo "Generating Admin API documentation..."
	@mkdir -p docs/specs
	swag init -g tools/prog/main.go -o docs/temp/admin --parseDependency --parseInternal --parseDepth 1 --tags Admin
	@mv docs/temp/admin/swagger.json docs/specs/admin-api.json
	@rm -rf docs/temp/admin
	@echo "Admin API documentation generated: docs/specs/admin-api.json"

# Install swag tool
docs-install:
	@echo "Installing swag tool..."
	go install github.com/swaggo/swag/cmd/swag@latest

# Generate Zod schemas from TypeScript types
generate-schemas: packages/slauth-ts/src/schemas/auth-api.schemas.ts packages/slauth-ts/src/schemas/admin-api.schemas.ts

# Generate auth API schemas
packages/slauth-ts/src/schemas/auth-api.schemas.ts: packages/slauth-ts/src/types/auth-api.ts packages/slauth-ts/ts-to-zod.config.js
	@echo "Generating Auth API Zod schemas..."
	@mkdir -p packages/slauth-ts/src/schemas
	@cd packages/slauth-ts && npx ts-to-zod --config auth-api
	@echo "Auth API schemas generated successfully!"

# Generate admin API schemas
packages/slauth-ts/src/schemas/admin-api.schemas.ts: packages/slauth-ts/src/types/admin-api.ts packages/slauth-ts/ts-to-zod.config.js
	@echo "Generating Admin API Zod schemas..."
	@mkdir -p packages/slauth-ts/src/schemas
	@cd packages/slauth-ts && npx ts-to-zod --config admin-api
	@echo "Admin API schemas generated successfully!"

# Run tests in tests/ directory
test:
	@echo "Running tests in tests/ directory..."
	@cd tests && go test -v ./...
	@echo "Tests completed!"

# Run tests with MySQL configuration
test-mysql:
	@echo "Running tests with MySQL configuration..."
	@cd tests && CONF_FILE=mysql.conf go test -v ./...
	@echo "MySQL tests completed!"

# Run tests with PostgreSQL configuration  
test-pgsql:
	@echo "Running tests with PostgreSQL configuration..."
	@cd tests && CONF_FILE=pgsql.conf go test -v ./...
	@echo "PostgreSQL tests completed!"

# Run tests with custom configuration file
# Usage: make test-custom CONF_FILE=your-config.conf
test-custom:
	@if [ -z "$(CONF_FILE)" ]; then \
		echo "Error: CONF_FILE environment variable is required"; \
		echo "Usage: make test-custom CONF_FILE=your-config.conf"; \
		exit 1; \
	fi
	@echo "Running tests with custom configuration: $(CONF_FILE)..."
	@cd tests && CONF_FILE=$(CONF_FILE) go test -v ./...
	@echo "Custom configuration tests completed!"

# Clean all generated files and build artifacts
clean:
	@echo "Cleaning generated files and build artifacts..."
	@rm -rf packages/slauth-ts/dist/
	@rm -rf packages/slauth-ui-vue/dist/
	@rm -rf packages/slauth-ts/src/schemas/
	@rm -rf docs/temp/
	@rm -rf tmp/
	@rm -rf demo/tmp/
	@rm -f pkg/consts/tmpl.go
	@rm -f packages/slauth-ts/src/types/auth-api.ts
	@rm -f packages/slauth-ts/src/types/admin-api.ts
	@rm -f docs/specs/auth-api.json
	@rm -f docs/specs/admin-api.json
	@echo "Clean completed!"

# Clean only schemas (useful for regenerating schemas without full clean)
clean-schemas:
	@echo "Cleaning generated schemas..."
	@rm -rf packages/slauth-ts/src/schemas/
	@echo "Schemas cleaned!"

# Force regenerate schemas (clean + generate)
regen-schemas: clean-schemas generate-schemas

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

# Help
help:
	@echo "Available targets:"
	@echo "  all         - Build everything (default)"
	@echo "  generate-templates - Generate tmpl.go from templates/"
	@echo "  generate-schemas - Generate Zod schemas from TypeScript types"
	@echo "  build-ts-sdk- Build TypeScript SDK"
	@echo "  build-vue-ui- Build Vue UI library"
	@echo "  docs-install- Install swag tool"
	@echo "  clean-schemas - Clean only generated schemas"
	@echo "  regen-schemas - Force regenerate schemas"
	@echo "  fmt         - Format Go code with gofmt -s"
	@echo "  lint        - Run golangci-lint"
	@echo "  lint-install- Install golangci-lint"
	@echo "  test        - Run tests in tests/ directory (default: SQLite)"
	@echo "  test-mysql  - Run tests with MySQL configuration"
	@echo "  test-pgsql  - Run tests with PostgreSQL configuration"
	@echo "  test-custom - Run tests with custom configuration file"
	@echo "  clean       - Clean all generated files and build artifacts"
	@echo ""
	@echo "Usage examples:"
	@echo "  make test                    # Run tests with SQLite (default)"
	@echo "  make test-mysql              # Run tests with MySQL"
	@echo "  make test-pgsql              # Run tests with PostgreSQL"
	@echo "  make test-custom CONF_FILE=my.conf  # Run tests with custom config"
	@echo "  CONF_FILE=mysql.conf make test     # Direct environment variable"
	@echo ""
	@echo "File targets:"
	@echo "  docs/specs/auth-api.json  - Generate auth API documentation"
	@echo "  docs/specs/admin-api.json - Generate admin API documentation"
	@echo "  packages/slauth-ts/src/types/auth-api.ts - Generate auth types"
	@echo "  packages/slauth-ts/src/types/admin-api.ts - Generate admin types"
