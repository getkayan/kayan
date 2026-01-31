FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=${VERSION:-dev}" \
    -o /kayan ./cmd/kayan

# -----------------------------------------------------------
# Production image
# -----------------------------------------------------------
FROM alpine:3.19

# Security: Run as non-root user
RUN addgroup -g 1000 kayan && \
    adduser -u 1000 -G kayan -s /bin/sh -D kayan

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /kayan /app/kayan

# Copy migrations (if applicable)
COPY --from=builder /app/migrations /app/migrations

# Set ownership
RUN chown -R kayan:kayan /app

USER kayan

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health/live || exit 1

# Run the application
ENTRYPOINT ["/app/kayan"]
CMD ["serve"]
