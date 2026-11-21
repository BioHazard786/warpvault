VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
SERVER_LDFLAGS = -s -w -X github.com/BioHazard786/warpvault/backend/internal/config.Version=$(VERSION)
CLI_LDFLAGS = -s -w -X github.com/BioHazard786/warpvault/cli/internal/version.Version=$(VERSION)

.PHONY: all build-frontend build-server build-cli build test run dev-web fixtures clean clean-data

all: build

# Vite writes straight into backend/web/dist, which the Go server embeds.
build-frontend:
	cd web && bun install --frozen-lockfile && bun run build

build-server:
	cd backend && CGO_ENABLED=0 go build -trimpath -ldflags="$(SERVER_LDFLAGS)" -o ../warpvault-server ./cmd/warpvault-server

build-cli:
	cd cli && CGO_ENABLED=0 go build -trimpath -ldflags="$(CLI_LDFLAGS)" -o ../warpvault .

build: build-frontend build-server build-cli

test:
	cd backend && go test ./...
	cd cli && go test ./...
	cd web && bun run test

run: build-frontend build-server
	./warpvault-server

# Vite dev server on :5173, proxying /api to a backend on :8080.
dev-web:
	cd web && bun run dev

# Regenerate protocol/fixtures/vectors.json (independent node:crypto vectors for the Go and web tests).
fixtures:
	cd web && bun scripts/gen-fixtures.mjs

# Build output only. Your local secrets live in ./data (see `make clean-data`), never touched here.
clean:
	rm -rf warpvault warpvault-server cli/dist
	find backend/web/dist -mindepth 1 ! -name .gitkeep -delete

# Deletes ./data: the SQLite database and every stored secret. Stop the server first.
clean-data:
	rm -rf data/
