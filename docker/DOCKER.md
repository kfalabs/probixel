# Docker Usage Guide

## Quick Start

### Using Docker Compose (Recommended)

1. **Create your configuration file and docker-compose.yml:**
   ```bash
   cp config.example.yaml docker/config.yaml
   cp docker/docker-compose.example.yml docker/docker-compose.yml
   # Edit files with your settings
   ```

2. **Build and run:**
   ```bash
   docker-compose -f docker/docker-compose.yml up -d
   ```

3. **View logs:**
   ```bash
   docker-compose logs -f probixel
   ```

4. **Stop the container:**
   ```bash
   docker-compose -f docker/docker-compose.yml down
   ```

### Using Docker CLI

1. **Build the image:**
   ```bash
   docker build -t kfalabs/probixel:latest -f docker/Dockerfile .
   ```

2. **Run the container:**
   ```bash
   # From Docker Hub
   docker run -d \
     --name probixel \
     -v $(pwd)/docker/config.yaml:/app/config.yaml:ro \
     --restart unless-stopped \
     kfalabs/probixel:latest

   # From GitHub Container Registry
   docker run -d \
     --name probixel \
     -v $(pwd)/docker/config.yaml:/app/config.yaml:ro \
     --restart unless-stopped \
     ghcr.io/kfalabs/probixel:latest
   ```

3. **View logs:**
   ```bash
   docker logs -f probixel
   ```

4. **Stop and remove:**
   ```bash
   docker stop probixel
   docker rm probixel
   ```

## Configuration

The container expects a configuration file at `/app/config.yaml`. You have several options:

### Option 1: Volume Mount (Recommended)
Mount your local config file:
```bash
-v $(pwd)/docker/config.yaml:/app/config.yaml:ro
```

### Option 2: Build-time Copy
Modify the Dockerfile to copy your config:
```dockerfile
COPY config.yaml .
```

### Option 3: ConfigMap (Kubernetes)
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: probixel-config
data:
  config.yaml: |
    global:
      default_interval: "1m"
    services:
      - name: "Internal API"
        type: "http"
        url: "https://internal-api.cluster.local/health"
        http:
          insecure_skip_verify: true
        monitor_endpoint:
          timeout: "10s"
          success:
            url: "https://webhook.site/success"
          failure:
            url: "https://webhook.site/failure"
            timeout: "5s"
```

## Network Modes

### Bridge Network (Default)
Suitable when monitoring external services:
```bash
docker run -d --name probixel -v $(pwd)/docker/config.yaml:/app/config.yaml:ro kfalabs/probixel:latest
```

### Host Network
Required when monitoring services on the Docker host:
```bash
docker run -d --name probixel --network host -v $(pwd)/docker/config.yaml:/app/config.yaml:ro kfalabs/probixel:latest
```

Or in docker-compose.yml:
```yaml
services:
  probixel:
    network_mode: "host"
```

## Ping Probe in Docker

The ping probe uses ICMP sockets which require kernel permission. The image runs as a
non-root user (UID 65532), so ICMP access depends on the host's `net.ipv4.ping_group_range`
sysctl. The probe automatically tries privileged (raw) ICMP first, then falls back to
unprivileged (UDP) ICMP.

If ping probes fail with "permission denied", allow unprivileged ICMP for all users:

```bash
docker run -d \
  --name probixel \
  --sysctl net.ipv4.ping_group_range="0 2147483647" \
  -v $(pwd)/docker/config.yaml:/app/config.yaml:ro \
  kfalabs/probixel:latest
```

Or in docker-compose.yml:
```yaml
services:
  probixel:
    sysctls:
      net.ipv4.ping_group_range: "0 2147483647"
```

> **Note:** Docker Desktop (macOS/Windows) typically allows unprivileged ICMP by default.
> This setting is mainly needed on Linux hosts where `ping_group_range` defaults to `1 0`.

## Advanced Usage

### Custom Entrypoint
```bash
docker run -it --rm \
  -v $(pwd)/docker/config.yaml:/app/config.yaml:ro \
  kfalabs/probixel:latest \
  -config /app/config.yaml -verbose
```

### Debug Mode
The production image uses a distroless base with no shell. To debug, you can use logs:
```bash
docker logs -f probixel
```

If you need shell access, build a debug image by replacing the final stage base with Alpine:
```dockerfile
FROM alpine:3 AS debug
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /build/probixel /app/probixel
ENTRYPOINT ["/bin/sh"]
```

Then run:
```bash
docker build --target debug -t probixel:debug -f docker/Dockerfile .
docker run -it --rm probixel:debug
```

### Resource Limits
```bash
docker run -d \
  --name probixel \
  --memory="128m" \
  --cpus="0.5" \
  -v $(pwd)/docker/config.yaml:/app/config.yaml:ro \
  kfalabs/probixel:latest
```

## Building for Multiple Architectures

The `Dockerfile` is optimized to use **native Go cross-compilation**, which avoids the slow QEMU emulation typically used for ARM builds on GitHub Actions. This allows building multi-platform images at native x86 speeds.

Build for ARM64 (e.g., Raspberry Pi):
```bash
docker buildx build --platform linux/arm64 -t probixel:arm64 -f docker/Dockerfile .
```

Build for multiple platforms:
```bash
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t kfalabs/probixel:latest -f docker/Dockerfile .
```

## Kubernetes Deployment

Example deployment:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: probixel
spec:
  replicas: 1
  selector:
    matchLabels:
      app: probixel
  template:
    metadata:
      labels:
        app: probixel
    spec:
      containers:
      - name: probixel
        image: kfalabs/probixel:latest
        resources:
          limits:
            memory: "128Mi"
            cpu: "500m"
          requests:
            memory: "64Mi"
            cpu: "100m"
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: probixel-config
```

## Troubleshooting

### Container exits immediately
Check logs:
```bash
docker logs probixel
```

Common issues:
- Missing or invalid config.yaml
- Config file not mounted correctly
- Permissions issues

### Cannot reach services
- Use `--network host` if monitoring localhost services
- Check firewall rules
- Verify DNS resolution inside container

### Config auto-reload not working
Ensure the config file is mounted as a volume (not copied at build time):
```bash
-v $(pwd)/docker/config.yaml:/app/config.yaml:ro
```
