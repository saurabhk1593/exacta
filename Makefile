.PHONY: run build test test-unit test-integ migrate-up migrate-down docker-up docker-down lint swagger clean

# ── Dev ───────────────────────────────────────────────────────────────────────
run:
	@go run ./cmd/server

run-watch:
	@air -c .air.toml

build:
	@CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/goauth ./cmd/server
	@echo "Binary: bin/goauth"

# ── Testing ───────────────────────────────────────────────────────────────────
test:
	@go test ./... -v -race -timeout 120s

test-unit:
	@go test ./internal/... -v -race -short

test-integ:
	@go test ./... -v -race -run Integration -timeout 120s

test-cover:
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ── Database ──────────────────────────────────────────────────────────────────
migrate-up:
	@migrate -path migrations -database "$(DB_URL)" up

migrate-down:
	@migrate -path migrations -database "$(DB_URL)" down 1

migrate-reset:
	@migrate -path migrations -database "$(DB_URL)" drop -f
	@migrate -path migrations -database "$(DB_URL)" up

migrate-status:
	@migrate -path migrations -database "$(DB_URL)" version

# ── Docker ────────────────────────────────────────────────────────────────────
docker-up:
	@docker compose up -d
	@echo "Waiting for services..."
	@sleep 3
	@docker compose run --rm migrate

docker-down:
	@docker compose down

docker-logs:
	@docker compose logs -f app

docker-reset:
	@docker compose down -v
	@docker compose up -d

# ── Code Quality ──────────────────────────────────────────────────────────────
lint:
	@golangci-lint run ./...

fmt:
	@gofmt -w .
	@goimports -w .

vet:
	@go vet ./...

# ── Docs ──────────────────────────────────────────────────────────────────────
swagger:
	@swag init -g cmd/server/main.go -o docs/

# ── Helpers ───────────────────────────────────────────────────────────────────
generate-secrets:
	@echo "JWT_ACCESS_SECRET=$$(openssl rand -hex 32)"
	@echo "JWT_REFRESH_SECRET=$$(openssl rand -hex 32)"

clean:
	@rm -rf bin/ coverage.out coverage.html

# Default DB URL for local dev
DB_URL ?= postgres://goauth:goauth_secret@localhost:5432/goauth?sslmode=disable
