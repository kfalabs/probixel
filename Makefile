.PHONY: help build run up down logs restart stop shell stats clean test

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the Docker image
	docker build -t probixel:latest .

run: ## Run container with Docker CLI
	@if [ ! -f config.yaml ]; then \
		echo "Error: config.yaml not found. Copy config.example.yaml to config.yaml first."; \
		exit 1; \
	fi
	docker run -d \
		--name probixel \
		-v $$(pwd)/config.yaml:/app/config.yaml:ro \
		--restart unless-stopped \
		probixel:latest

up: ## Start with docker-compose
	docker-compose up -d

down: ## Stop docker-compose
	docker-compose down

logs: ## View container logs
	@if docker-compose ps | grep -q probixel; then \
		docker-compose logs -f probixel; \
	else \
		docker logs -f probixel; \
	fi

restart: ## Restart the container
	@if docker-compose ps | grep -q probixel; then \
		docker-compose restart probixel; \
	else \
		docker restart probixel; \
	fi

stop: ## Stop and remove container
	docker stop probixel || true
	docker rm probixel || true

shell: ## Open shell in running container
	docker exec -it probixel /bin/sh

stats: ## Show container resource usage
	docker stats probixel --no-stream

clean: ## Remove unused Docker images
	docker image prune -f

test: ## Run Go tests
	go test -v ./...

lint: ## Run linter
	golangci-lint run ./...

build-native: ## Build native binary
	go build -o probixel ./cmd

run-native: ## Run native binary
	./probixel -config config.yaml

# Multi-architecture builds
build-arm64: ## Build for ARM64 (e.g., Raspberry Pi)
	docker buildx build --platform linux/arm64 -t probixel:arm64 .

build-multi: ## Build for multiple architectures
	docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t probixel:latest .
