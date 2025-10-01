# E2E testing targets

.PHONY: e2e-up e2e-down e2e-test e2e-logs e2e-full

# Start E2E environment
e2e-up:
	@echo "Building frontend for E2E..."
	$(MAKE) all
	@echo "Starting E2E environment..."
	docker-compose -f docker/docker-compose.dev-infra.yml up -d postgres redis mailhog smshog
	@sleep 5
	docker-compose -f docker/docker-compose.dev-infra.yml up -d backend
	@sleep 5
	docker-compose -f docker/docker-compose.dev-infra.yml up -d frontend
	@echo "E2E environment ready!"
	@echo "Frontend: http://localhost:15180"
	@echo "Backend:  http://localhost:18080"
	@echo "MailHog:  http://localhost:18025"
	@echo "SMSHog:   http://localhost:18026"

# Stop E2E environment
e2e-down:
	@echo "Stopping E2E environment..."
	docker-compose -f docker/docker-compose.dev-infra.yml down -v

# Run E2E tests
e2e-test:
	@echo "Running E2E tests..."
	docker-compose -f docker/docker-compose.dev-infra.yml run --rm e2e-tests

# View logs
e2e-logs:
	docker-compose -f docker/docker-compose.dev-infra.yml logs -f

# Full E2E workflow
e2e-full: e2e-up
	@sleep 10
	$(MAKE) e2e-test
	$(MAKE) e2e-down

