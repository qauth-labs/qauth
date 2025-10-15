# Makefile for QAuth OAuth 2.1/OIDC Server
# Provides convenient commands for development and deployment

.PHONY: help install dev build test lint format clean docker-up docker-down docker-logs db-migrate db-studio

# =============================================================================
# Help
# =============================================================================

help: ## Show this help message
	@echo "QAuth OAuth 2.1/OIDC Server - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# =============================================================================
# Development Commands
# =============================================================================

install: ## Install dependencies
	pnpm install

dev: ## Start development server
	pnpm nx serve auth-server

build: ## Build all projects
	pnpm nx run-many --target=build --all

test: ## Run tests
	pnpm nx run-many --target=test --all

lint: ## Run linting
	pnpm nx run-many --target=lint --all

format: ## Format code
	pnpm format

clean: ## Clean build artifacts
	pnpm nx reset
	rm -rf dist
	rm -rf node_modules/.cache

# =============================================================================
# Database Commands
# =============================================================================

db-generate: ## Generate database migrations
	pnpm db:generate

db-migrate: ## Run database migrations
	pnpm db:migrate

db-push: ## Push schema to database (development only)
	pnpm db:push

db-studio: ## Open Drizzle Studio
	pnpm db:studio

# =============================================================================
# Docker Commands
# =============================================================================

docker-up: ## Start Docker services (PostgreSQL + Redis)
	docker-compose up -d

docker-down: ## Stop Docker services
	docker-compose down

docker-logs: ## Show Docker logs
	docker-compose logs -f

docker-restart: ## Restart Docker services
	docker-compose restart

docker-clean: ## Stop and remove Docker containers and volumes
	docker-compose down -v --remove-orphans

# =============================================================================
# Production Docker Commands
# =============================================================================

docker-prod-up: ## Start production Docker services
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

docker-prod-down: ## Stop production Docker services
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml down

docker-prod-logs: ## Show production Docker logs
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml logs -f

# =============================================================================
# Development Tools
# =============================================================================

tools-up: ## Start development tools (Redis Commander, pgAdmin)
	docker-compose --profile tools up -d

tools-down: ## Stop development tools
	docker-compose --profile tools down

# =============================================================================
# Setup Commands
# =============================================================================

setup: install docker-up db-generate db-push ## Complete development setup

setup-prod: install docker-prod-up db-generate db-migrate ## Complete production setup

# =============================================================================
# Health Checks
# =============================================================================

health: ## Check service health
	@echo "Checking service health..."
	@curl -s http://localhost:3000/health | jq . || echo "Server not running"
	@echo ""
	@echo "Database connection:"
	@docker-compose exec postgres pg_isready -U qauth -d qauth_dev || echo "Database not ready"
	@echo ""
	@echo "Redis connection:"
	@docker-compose exec redis redis-cli ping || echo "Redis not ready"

# =============================================================================
# Utility Commands
# =============================================================================

logs: ## Show application logs
	pnpm nx serve auth-server --verbose

reset: clean docker-clean ## Reset everything (clean + docker-clean)
	pnpm install

# =============================================================================
# Default Target
# =============================================================================

.DEFAULT_GOAL := help
