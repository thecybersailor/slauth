# Test targets

.PHONY: test test-mysql test-pgsql test-custom reset-test-db

# Helper function to reset database
# Usage: make reset-test-db CONF_FILE=pgsql.conf
reset-test-db:
	@if [ -z "$(CONF_FILE)" ]; then \
		echo "Error: CONF_FILE is required"; \
		exit 1; \
	fi
	@echo "Resetting test database using $(CONF_FILE)..."
	@bash tools/mk/reset-db-helper.sh tests/$(CONF_FILE)

# Run tests in tests/ directory
test:
	@echo "Running tests in tests/ directory..."
	@cd tests && go test -v ./...
	@touch .checks-passed
	@echo "Tests completed and marked as passed!"

# Run tests with MySQL configuration
test-mysql:
	@if [ "$$RESET_DB" = "true" ]; then \
		echo "RESET_DB=true detected, resetting MySQL database..."; \
		bash tools/mk/reset-db-helper.sh tests/mysql.conf; \
	fi
	@echo "Running tests with MySQL configuration..."
	@cd tests && CONF_FILE=mysql.conf go test -v ./...
	@touch .checks-passed
	@echo "MySQL tests completed and marked as passed!"

# Run tests with PostgreSQL configuration  
test-pgsql:
	@if [ "$$RESET_DB" = "true" ]; then \
		echo "RESET_DB=true detected, resetting PostgreSQL database..."; \
		bash tools/mk/reset-db-helper.sh tests/pgsql.conf; \
	fi
	@echo "Running tests with PostgreSQL configuration..."
	@cd tests && CONF_FILE=pgsql.conf go test -v ./...
	@touch .checks-passed
	@echo "PostgreSQL tests completed and marked as passed!"

# Run tests with custom configuration file
# Usage: make test-custom CONF_FILE=your-config.conf
# Usage with reset: RESET_DB=true make test-custom CONF_FILE=your-config.conf
test-custom:
	@if [ -z "$(CONF_FILE)" ]; then \
		echo "Error: CONF_FILE environment variable is required"; \
		echo "Usage: make test-custom CONF_FILE=your-config.conf"; \
		exit 1; \
	fi
	@if [ "$$RESET_DB" = "true" ]; then \
		echo "RESET_DB=true detected, resetting database..."; \
		bash tools/mk/reset-db-helper.sh tests/$(CONF_FILE); \
	fi
	@echo "Running tests with custom configuration: $(CONF_FILE)..."
	@cd tests && CONF_FILE=$(CONF_FILE) go test -v ./...
	@touch .checks-passed
	@echo "Custom configuration tests completed and marked as passed!"

