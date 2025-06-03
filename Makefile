.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make build         - Build Docker image"
	@echo "  make push          - Push image to registry"
	@echo "  make deploy        - Deploy to Kubernetes"
	@echo "  make migrate-prod  - Run database migrations in production"
	@echo "  make logs          - Show production logs"
	@echo "  make rollback      - Rollback to previous deployment"

.PHONY: build
build:
	docker build -t ghcr.io/rsolv-dev/rsolv-api:latest .

.PHONY: push
push:
	docker push ghcr.io/rsolv-dev/rsolv-api:latest

.PHONY: deploy
deploy:
	kubectl apply -f k8s/

.PHONY: migrate-prod
migrate-prod:
	./scripts/run-migrations-prod.sh

.PHONY: logs
logs:
	kubectl logs -f -l app=rsolv-api --tail=100

.PHONY: rollback
rollback:
	kubectl rollout undo deployment/rsolv-api

# Development commands
.PHONY: dev
dev:
	docker-compose up

.PHONY: test
test:
	docker-compose run --rm rsolv-api mix test

.PHONY: migrate-dev
migrate-dev:
	docker-compose run --rm rsolv-api mix ecto.migrate

.PHONY: reset-db
reset-db:
	docker-compose run --rm rsolv-api mix ecto.reset