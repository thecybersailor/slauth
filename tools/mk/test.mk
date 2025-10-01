# Test targets

.PHONY: test test-mysql test-pgsql test-custom

# Run tests in tests/ directory
test:
	@echo "Running tests in tests/ directory..."
	@cd tests && go test -v ./...
	@touch .test-passed
	@echo "Tests completed and marked as passed!"

# Run tests with MySQL configuration
test-mysql:
	@echo "Running tests with MySQL configuration..."
	@cd tests && CONF_FILE=mysql.conf go test -v ./...
	@touch .test-passed
	@echo "MySQL tests completed and marked as passed!"

# Run tests with PostgreSQL configuration  
test-pgsql:
	@echo "Running tests with PostgreSQL configuration..."
	@cd tests && CONF_FILE=pgsql.conf go test -v ./...
	@touch .test-passed
	@echo "PostgreSQL tests completed and marked as passed!"

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
	@touch .test-passed
	@echo "Custom configuration tests completed and marked as passed!"

