.PHONY: build run test lint docker-up docker-down migrate-up migrate-down migrate-create stack-up stack-down stack-logs

BINARY     := bin/server
DB_URL     ?= postgres://envsh:envsh@localhost:5432/envsh?sslmode=disable
MIGRATIONS := migrations

build:
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/server

run: build
	./$(BINARY)

test:
	go test -race -timeout 120s ./...

lint:
	@which golangci-lint > /dev/null || (echo "Install: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

docker-up:
	docker compose up -d

docker-down:
	docker compose down

migrate-up:
	migrate -path $(MIGRATIONS) -database "$(DB_URL)" up

migrate-down:
	migrate -path $(MIGRATIONS) -database "$(DB_URL)" down 1

migrate-create:
	@test -n "$(NAME)" || (echo "Usage: make migrate-create NAME=description" && exit 1)
	migrate create -ext sql -dir $(MIGRATIONS) -seq $(NAME)

stack-up:
	docker compose -f docker-compose.full.yml up -d --build

stack-down:
	docker compose -f docker-compose.full.yml down

stack-logs:
	docker compose -f docker-compose.full.yml logs -f server
