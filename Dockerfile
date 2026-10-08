# Stage 1: Build Frontend (Astro + Tailwind v4)
# ==========================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app/web

# Copy package.json and install dependencies
COPY web/package.json ./
RUN npm install

# Copy source and root environment files
WORKDIR /app
COPY web/ ./web/
COPY .env* ./

# Build arguments with fallback defaults
ARG WARPVAULT_MAX_SECRET_SIZE_MB=25
ENV WARPVAULT_MAX_SECRET_SIZE_MB=$WARPVAULT_MAX_SECRET_SIZE_MB

# Build frontend static bundle
WORKDIR /app/web
RUN npm run build

# ==========================================
# Stage 2: Build Backend (Go 1.26 Static Binaries)
# ==========================================
FROM golang:1.26-alpine AS backend-builder
WORKDIR /app

# Install CA certificates and timezone database
RUN apk --no-cache add ca-certificates tzdata

# Create unprivileged non-root user (UID 10001) and storage directory
RUN adduser -D -u 10001 -g "" -s /sbin/nologin warpvault && \
    mkdir -p /data/storage && \
    chown -R 10001:10001 /data

# Download Go module dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and compiled static frontend from Stage 1
COPY . .
COPY --from=frontend-builder /app/web/dist ./web/dist

# Build fully static server and CLI binaries (zero CGO)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/warpvault-server ./cmd/warpvault-server && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/warpvault ./cmd/warpvault

# ==========================================
# Stage 3: Ultra-Minimal Production Runner
# ==========================================
FROM scratch AS runner

WORKDIR /app

# System certificates and timezone data
COPY --from=backend-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=backend-builder /usr/share/zoneinfo /usr/share/zoneinfo

# Non-root user and pre-configured data directory
COPY --from=backend-builder /etc/passwd /etc/passwd
COPY --from=backend-builder --chown=10001:10001 /data /data

# Binaries (Server and standalone CLI)
COPY --from=backend-builder /app/warpvault-server /app/warpvault-server
COPY --from=backend-builder /app/warpvault /app/warpvault

# Run as non-root user
USER 10001:10001

# Default Environment Variables
ENV WARPVAULT_PORT=8080 \
    WARPVAULT_BASE_URL=http://localhost:8080 \
    WARPVAULT_STORAGE_PATH=/data/storage \
    WARPVAULT_DB_PATH=/data/warpvault.db \
    WARPVAULT_MAX_SECRET_SIZE_MB=25 \
    WARPVAULT_DEFAULT_EXPIRY=burn \
    WARPVAULT_ALLOWED_EXPIRIES=burn,1h,12h,24h,72h \
    WARPVAULT_TRUST_PROXY=false \
    WARPVAULT_LOG_FORMAT=json \
    WARPVAULT_LOG_LEVEL=info

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/app/warpvault-server"]
