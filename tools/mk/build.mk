# Build and documentation targets

.PHONY: all build-ts-sdk build-vue-ui generate-templates generate-schemas regen-schemas clean-schemas docs-install generate-llms

# Default target
all: generate-templates generate-schemas build-ts-sdk build-vue-ui generate-llms

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

# Clean only schemas (useful for regenerating schemas without full clean)
clean-schemas:
	@echo "Cleaning generated schemas..."
	@rm -rf packages/slauth-ts/src/schemas/
	@echo "Schemas cleaned!"

# Force regenerate schemas (clean + generate)
regen-schemas: clean-schemas generate-schemas

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

# Generate llms.txt files for all packages
generate-llms:
	@echo "Generating llms.txt files..."
	@node tools/generate-llms.mjs
	@echo "llms.txt files generated successfully!"
