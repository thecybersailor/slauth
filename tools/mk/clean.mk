# Clean targets

.PHONY: clean

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

