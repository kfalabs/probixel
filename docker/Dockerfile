# Build stage
FROM --platform=$BUILDPLATFORM golang:1.26.1-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

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

# Final stage - distroless for minimal attack surface.
FROM gcr.io/distroless/static-debian13:nonroot

# Copy timezone data from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Keep all timestamps on UTC by default
ENV TZ=UTC

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/probixel .

# Run the application
ENTRYPOINT ["/app/probixel"]
CMD ["-config", "/app/config.yaml"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/app/probixel", "-health"]
