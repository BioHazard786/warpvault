.PHONY: all build-frontend build-server build-cli build test run clean docker-build docker-up

all: build

build-frontend:
	cd web && pnpm install && pnpm build

build-server:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o warpvault-server ./cmd/warpvault-server

build-cli:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o warpvault ./cmd/warpvault

build: build-frontend build-server build-cli

test:
	go test -v ./...

run: build-frontend build-server
	./warpvault-server

docker-build:
	docker compose build

docker-up:
	docker compose up -d

clean:
	rm -rf warpvault warpvault-server web/dist data/
