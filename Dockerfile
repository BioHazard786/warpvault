# syntax=docker/dockerfile:1
# ==========================================
# Stage 1: Build the SPA (Vite + React, Bun)
# ==========================================
FROM --platform=$BUILDPLATFORM oven/bun:1.4-alpine AS frontend-builder
WORKDIR /src/web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun x vite build --outDir /out --emptyOutDir

# ==========================================
# Stage 2: Build Backend (Go static binary)
# ==========================================
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS backend-builder
WORKDIR /src/backend

# Storage directory, owned by the runtime user (UID 10001). A new named volume inherits this ownership.
RUN mkdir -p /data/storage && chown -R 10001:10001 /data

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
COPY --from=frontend-builder /out ./web/dist

ARG TARGETOS
ARG TARGETARCH
ARG WARPVAULT_VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/BioHazard786/warpvault/backend/internal/config.Version=${WARPVAULT_VERSION}" \
    -o /app/warpvault-server ./cmd/warpvault-server

# ==========================================
# Stage 3: Minimal runner (distroless: CA certs, tzdata, no shell)
# ==========================================
FROM gcr.io/distroless/static:nonroot AS runner
WORKDIR /app

COPY --from=backend-builder --chown=10001:10001 /data /data
COPY --from=backend-builder /app/warpvault-server /app/warpvault-server

USER 10001:10001

ENV WARPVAULT_PORT=8080 \
    WARPVAULT_BASE_URL=http://localhost:8080 \
    WARPVAULT_STORAGE_PATH=/data/storage \
    WARPVAULT_DB_PATH=/data/warpvault.db \
    WARPVAULT_DEFAULT_EXPIRY=burn \
    WARPVAULT_ALLOWED_EXPIRIES=burn,1h,12h,24h,72h \
    WARPVAULT_TRUST_PROXY=false \
    WARPVAULT_LOG_FORMAT=json \
    WARPVAULT_LOG_LEVEL=info

VOLUME ["/data"]
EXPOSE 8080

# No curl in the image; the binary probes its own /healthz.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["/app/warpvault-server", "-healthcheck"]

ENTRYPOINT ["/app/warpvault-server"]
