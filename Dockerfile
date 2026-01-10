# Build stage
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# ARGs for cross-compilation (populated automatically by Docker Buildx)
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# Build the application
# CGO_ENABLED=0 for static binary, -ldflags for smaller binary
# Using cache mounts for go build and mod cache
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    CGO_ENABLED=0 go build -a -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -o probixel ./cmd

# Final stage - use alpine for minimal size.
FROM alpine:3

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user for security
RUN addgroup -g 1000 probixel && \
    adduser -D -u 1000 -G probixel probixel

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/probixel .

# Change ownership to non-root user
RUN chown -R probixel:probixel /app

# Switch to non-root user
USER probixel

# Run the application
ENTRYPOINT ["/app/probixel"]
CMD ["-config", "/app/config.yaml"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/app/probixel", "-health"]
