# Probixel
![Coverage](https://img.shields.io/badge/Coverage-97.9%25-brightgreen)

A lightweight, configurable monitoring agent written in Go that checks the health of various services and sends alerts to configured endpoints such as Healthchecks.io, Uptime Kuma, Gatus, and more.

This is not meant to replace an actual monitoring service, but to serve as a local agent that monitors your stack and sends the results (whether success/failure) to a monitoring service.

This solves the problem of monitoring services that are behind a firewall and are not accessible from the internet.

***Note:** This project was developed with the assistance of AI coding agents.*

[![Tests](https://github.com/kfalabs/probixel/actions/workflows/test.yml/badge.svg)](https://github.com/kfalabs/probixel/actions/workflows/test.yml)
[![Release](https://github.com/kfalabs/probixel/actions/workflows/release.yml/badge.svg)](https://github.com/kfalabs/probixel/actions/workflows/release.yml)

## Features

- **HTTP(s)/TCP/UDP/DNS/Host/SSH Monitoring**: Monitor various endpoints, including the host and SSH accessibility.
- **Docker Monitoring**: Monitor container status and health via local Unix sockets or HTTP/HTTPS proxies
- **Tunnel Infrastructure**: Integrated SSH and WireGuard tunnels with auto-healing and stabilization
- **Intelligent Response Matching**: Validate HTTP response bodies (JSON, text) and headers
  - **Expectations**: Support for `==`, `>`, `<`, `contains`, and `matches` with intelligent type detection
  - **JSON Path**: Deep traversal and wildcard support (powered by [gjson](https://github.com/tidwall/gjson))
- **Config file Driven**: YAML-based config with auto-reload.
- **Target Modes**: Monitor multiple targets with `any` (failover) or `all` (cluster) modes
- **Integrated Tunnel Transport**: Route any probe (HTTP, TCP, DNS, etc.) through WireGuard or SSH tunnels
- **Multi-architecture**: Native Go cross-compilation for multi-architecture Docker builds

### Native Installation

It has not been tested on Windows, but it should probably work. It has been tested on Linux and macOS.

```bash
# Clone the repository
git clone https://github.com/kfalabs/probixel.git
cd probixel

# Build the agent
make build-native

# Run the agent
./probixel -config config.yaml
```

### CLI Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-config` | Path to the YAML configuration file. | `config.yaml` |
| `-pidfile` | Path to write the process PID file. | `/tmp/probixel.pid` |
| `-health` | Perform a health check (is the process running?) and exit. | `false` |
| `-delay` | Starting window delay in seconds (0 to disable). | `10` |

### Docker Installation

```bash
# Using Docker Compose (recommended)
cp config.example.yaml docker/config.yaml
cp docker/docker-compose.example.yml docker/docker-compose.yml
# Edit docker/config.yaml and docker/docker-compose.yml with your settings
docker-compose -f docker/docker-compose.yml up -d

# Or using Docker Hub
docker pull kfalabs/probixel:latest
docker run -d --name probixel -v $(pwd)/docker/config.yaml:/app/config.yaml:ro kfalabs/probixel:latest

# Or using GHCR
docker pull ghcr.io/kfalabs/probixel:latest
docker run -d --name probixel -v $(pwd)/docker/config.yaml:/app/config.yaml:ro ghcr.io/kfalabs/probixel:latest
```

For detailed Docker usage, configuration options, and deployment examples, see [DOCKER.md](docker/DOCKER.md).

## Configuration Auto-Reload

The agent automatically watches the configuration file for changes and reloads it. When you modify the config file:

- A **10-second debounce delay** is applied after detecting a change, preventing rapid reloads during multi-edit saves
- **All monitoring services are restarted** to ensure that changes to intervals and other settings take effect immediately
- Invalid config changes are logged and ignored (old config remains active)

This allows you to update intervals, alert endpoints, headers, and other settings on-the-fly.

## Starting Window

The agent implements a configurable **starting window** (default: 10 seconds) that delays the start of service monitors after:
- Initial application startup
- Configuration reloads

This grace period ensures that:
- Tunnels (SSH, WireGuard) are fully initialized
- External dependencies (Docker sockets, network interfaces) are ready
- False alerts are prevented during infrastructure stabilization

The starting window can be configured via the `-delay` flag:
```bash
# Default 10-second delay
./probixel -config config.yaml

# No delay (useful for testing)
./probixel -config config.yaml -delay 0

# Custom 30-second delay
./probixel -config config.yaml -delay 30
```

## Configuration
An example configuration file is provided in [config.example.yaml](https://github.com/kfalabs/probixel/blob/main/config.example.yaml). Copy this file to `config.yaml` and modify it to suit your needs.

## Configuration Reference

### Global Configuration
The `global` block allows you to set defaults for all services:

```yaml
global:
  default_interval: "5m"
  monitor_endpoint:
    timeout: "10s" # Optional global default timeout for alert notifications, defaults to 5s.
    retries: 3 # Global default retries for alert notifications.
    headers:
      Authorization: "Bearer your-common-token"
      X-Environment: "production"
  monitor:
    retries: 3 # Global default retries for probes. Use "0" to disable.
  notifier:
    rate_limit: "100ms"
```

- **`default_interval`**: Applied to any service that doesn't specify its own `interval`. This is optional only if **all** services have their own explicit intervals.
- **`timeout`**: (Global) Default timeout for all alert notifications (success/failure) sent by any service. Defaults to `5s` if not specified.
- **Global Headers**: These headers are automatically included in **every** alert notification (success or failure) sent by any service. Use this for common authentication tokens or environment metadata. Remember that headers defined at the monitor endpoint level of services override global headers.
- **Notification Rate Limit**: The `notifier.rate_limit` field (e.g., `100ms`, `1s`) sets a global cooldown between notification pushes to prevent hitting API rate limits (like Cloudflare or Discord). 
  - **Default**: 100ms
  - **Disable**: Set to `"0"`
  - **Validation**: An empty string is invalid and will cause the configuration to fail.

### Retry Logic

Both **Probes** (checks) and **Notifiers** (alerts) support automatic retries on failure.

#### Configuration Hierarchy
Retries can be configured at the global level and overridden at the service level:

1. **Service Override**: `service.retries` / `service.monitor_endpoint.retries`
2. **Global Default**: `global.monitor.retries` / `global.monitor_endpoint.retries`
3. **Hardcoded Default**: `3` (if neither is set)

> [!TIP]
> **Disabling Retries**: Setting `retries: 0` (either globally or at the service level) effectively disables the retry logic. This is particularly useful for meeting strict validation rules when the timeout and interval are very close.

#### Validation Rules
To ensure monitoring cycles don't overlap, the total potential duration of a check or alert push must fit within the service interval:

**Formula**: `(retries + 1) * timeout + 1s (buffer) < interval`

**Exemptions**: 
- `host` and `wireguard` probes are exempt from retry validation (forced to 0 retries).

### Docker Sockets

The `docker-sockets` root block allows you to define one or more Docker daemon connections that can be referenced by Docker services. You can specify multiple sockets for different environments or configurations.

```yaml
docker-sockets:
  local:
    socket: "/var/run/docker.sock"
  proxy:
    host: "docker-proxy"
    port: 2375
    protocol: "http" # Optional, defaults to http
    headers: # Optional headers for the proxy
      Authorization: "Basic <creds>"
```

### Tunnels

The `tunnels` root block allows you to define underlying network transport layers. Tunnels are infrastructure components that handle the connection lifecycle, while services use them for monitoring or transport.

- **Reactive Monitoring**: Tunnels are monitored by the services that use them. If a service dial fails, it reports a failure to the tunnel. After a threshold of failures, the tunnel is automatically restarted.

#### WireGuard Tunnel Health & Restart Logic

- **Global Starting Window**: On application startup or configuration reload, there is a configurable delay (default 10 seconds, adjustable via `-delay` flag) before any service monitors begin.
- **Health Tracking**: 
  - Success is reported when any service check (HTTP, TCP, ping, etc.) completes successfully through the tunnel, or when the WireGuard probe detects a recent handshake
  - The tunnel is considered healthy if EITHER:
    - **Handshake is recent** (< 5 minutes), OR
    - **Success is recent** (within success window: `(max_interval * restart_threshold) + 60s`, where max_interval is the largest interval of any service using the tunnel)
  - Services using the tunnel do NOT perform handshake checks - they only verify their own connectivity
- **Restart Logic**: 
  - The WireGuard probe triggers a restart if handshake exceeds `max_age` (after stabilization)
  - When services fail, the tunnel checks both handshake and success timestamps before restarting
  - Restart occurs only if BOTH handshake is stale (> 5 min) AND no success within the success window

#### Reusable Tunnel Configuration
Once defined in the root `tunnels` block, a tunnel can be referenced by any service using the `tunnel: <name>` property. This decouples the network setup from the specific health checks you want to perform.

#### Configuration
```yaml
tunnels:
  office-vpn:
    type: "wireguard"
    wireguard:
      endpoint: "vpn.example.com:51820"
      public_key: "..."
      private_key: "..."
      addresses: "10.64.0.5/32"
      restart_threshold: 1 # Optional, min 1. Number of failures before triggering a restart.
  secure-ssh:
    type: "ssh"
    target: "bastion.example.com"
    ssh:
      user: "tunnel-user"
      private_key: "..."
```

#### Integrated Tunnel Transport
Any probe type (`http`, `tcp`, `dns`, `udp`, `tls`, `ssh`, `docker`) can route its traffic through a defined tunnel. By setting `tunnel: <name>` at the service level, the probe automatically uses the tunnel.

This allows you to perform health checks against internal targets without complex networking:
- **HTTP/DNS-over-VPN**: Reach internal portals or private search domains.
- **TCP-over-SSH**: Perform database health checks behind an SSH bastion.
- **Integrated Dialing**: Traffic is routed directly in-process; no system-level routing changes are required.
- **Stabilization Awareness**: Probes are "tunnel-aware"; if an underlying tunnel is still stabilizing (handshaking), the probe will report `WAITING` instead of `DOWN`, inhibiting premature failure reports.

### Services / Probe Types

The following sections describe each supported probe type and their configuration options.

#### HTTP
Monitors HTTP/HTTPS endpoints with optional "intelligent" response validation.
- **Fields**: `url` (required), `timeout` (optional), `http:` block (optional)
- **HTTP Block**: `method` (optional), `headers` (optional), `accepted_status_codes` (optional, string e.g., "200-299, 404"), `insecure_skip_verify` (optional), `match_data` (optional), `certificate_expiry` (optional)
- **Example**:
  ```yaml
    type: "http"
    interval: "5m" # Required if the global `default_interval` is not set
    url: "https://example.test"
    timeout: "5s" # Optional service-level timeout, defaults to 5s.
    tunnel: "office-vpn" # Optional, tunnel name.
    http: # Optional HTTP block.
      method: "GET" # Optional, defaults to GET.
      accepted_status_codes: "200-299" # Optional, defaults to "200-399"
      insecure_skip_verify: true # Optional, defaults to false. Set to true for self-signed or invalid certificates.
      certificate_expiry: "2d" # Optional. Set to a duration to check the certificate expiry.
      headers: # These headers are only for the probe request, not for the alert endpoint. Ensure that you do not send sensitive information to your alert endpoints.
        User-Agent: "Probixel/1.0"
      match_data: # Optional match data block for response validation.
        expectations:
          - type: "json"
            json_path: "status"
            operator: "=="
            value: "healthy"
          - type: "json"
            json_path: "last_sync"
            operator: "<"
            value: "10m" # Ensures age is less than 10 minutes
    monitor_endpoint:
      timeout: "10s" # Optional service-level timeout for both success and failure endpoints.
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
        method: "POST" # Optional: defaults to GET
        timeout: "15s" # Optional endpoint-specific timeout, overrides service and global settings.
        insecure_skip_verify: true # Optional, defaults to false. Set to true for self-signed or invalid certificates.
        headers: # Optional headers for the success endpoint, will use global headers if not specified.
          Content-Type: "application/json"
          Authorization: "Bearer your-token"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
        timeout: "5s" # Optional endpoint-specific timeout.
  ```
### Match Data Configuration
The `match_data` block allows you to validate the response body or headers.

- **Supported Types**: `json`, `body`, `header`
- **Supported Value Types**: `String`, `Number`, `Duration (Age)`, `Timestamp`
- **Supported Operators**: `==`, `>`, `<`, `contains`, `matches`

##### Supported Match Operators
| Operator | Description | Sub-types Handled |
| :--- | :--- | :--- |
| `==` | Equality | String, Number |
| `>` | Greater Than | Number, Duration (Age), Timestamp |
| `<` | Less Than | Number, Duration (Age), Timestamp |
| `contains` | Substring Match | String |
| `matches` | Regular Expression | Regex |

**Note on Time Comparisons**: If the `value` is a duration (e.g., `10m`), Probixel automatically parses the response field as a timestamp and checks if its age (`now - last_sync`) is within that limit.

If the `certificate_expiry` and `match_data` are both provided, the probe will run both checks and fail if either check fails.

#### TLS Check
- **Fields**: `url` (required), `timeout` (optional), `tls:` block (required)
- **TLS Block**: `insecure_skip_verify` (optional), `certificate_expiry` (required)
- **Example**:
  ```yaml
  - name: "TLS Check"
    type: "tls"
    interval: "5m" # Required if the global `default_interval` is not set
    url: "tls://example.test"
    timeout: "5s" # Optional service-level timeout, defaults to 5s.
    tunnel: "office-vpn" # Optional, tunnel name.
    tls:
      insecure_skip_verify: true # Optional, defaults to false. Set to true for self-signed or invalid certificates.
      certificate_expiry: "2d" # Required. Set to a duration to check the certificate expiry.
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

#### TCP
Checks TCP port connectivity.
- **Fields**: `targets` (required), `target_mode` (optional), `timeout` (optional)
- **Format**: `host:port`
- **Example**:
  ```yaml
  - name: "TCP Check"
    type: "tcp"
    tunnel: "office-vpn" # Optional, tunnel name.
    timeout: "5s" # Optional service-level timeout, defaults to 5s.
    interval: "5m" # Required if the global `default_interval` is not set
    targets: ["host1:5000", "host2:5001"] # Supports either a **YAML array** or a **comma-separated string**
    target_mode: "any" # Optional, defaults to "any". Set to "all" to fail if all targets are unreachable.
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

#### UDP
Verifies UDP port reachability.
- **Configuration Block**: `udp:` (Uses the TCP target logic)
- **Fields**: `targets` (required), `timeout` (optional)
- **Format**: `host:port`
- **Note**: UDP is connectionless; probe validates socket creation and write capability
- **Example**:
  ```yaml
  - name: "Remote Syslog"
    type: "udp"
    tunnel: "office-vpn" # Optional, tunnel name.
    timeout: "5s" # Optional, defaults to 5s.
    interval: "5m" # Required if the global `default_interval` is not set
    targets: ["syslog.example.com:514", "syslog2.example.com:514"] # Supports either a **YAML array** or a **comma-separated string**
    target_mode: "any" # Optional, defaults to "any". Set to "all" to fail if all targets are unreachable.
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

#### DNS
- **Fields**: `targets` (required — nameserver addresses to query), `target_mode` (optional), `timeout` (optional), `dns:` block (optional)
- **DNS Block**: `domain` (optional, defaults to `google.com` — the domain to resolve against the nameservers)
- **Format**: `host:port` (port defaults to `53` if omitted). Resolves via UDP first, retries with TCP on failure.
- **Example**:
  ```yaml
  - name: "DNS Servers"
    type: "dns"
    tunnel: "office-vpn" # Optional, tunnel name.
    interval: "5m" # Required if the global `default_interval` is not set
    targets: ["8.8.8.8:53", "1.1.1.1:53"]
    timeout: "5s" # Optional, defaults to 5s.
    dns:
      domain: "example.test" # Optional, defaults to "google.com". This is the domain to query.
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

#### Ping
- **Fields**: `targets` (required), `target_mode` (optional), `timeout` (optional)
- **Execution strategies** (automatic fallback):
  1. **Built-in ICMP** — Used when routed through a tunnel with `DialContext` support
  2. **Remote SSH ping** — Falls back to executing `ping` on the remote host when ICMP is unsupported (e.g., SSH tunnels)
  3. **System `ping` executable** — Default when no tunnel is set (cross-platform: macOS, Linux, Windows)
- **Example**:
  ```yaml
  - name: "Ping Targets"
    type: "ping"
    tunnel: "office-vpn" # Optional, tunnel name.
    timeout: "5s" # Optional, defaults to 5s.
    interval: "5m" # Required if the global `default_interval` is not set
    targets: ["127.0.0.1", "test.local"] # Supports either a **YAML array** or a **comma-separated string**
    target_mode: "any" # Optional, defaults to "any". Set to "all" to fail if all targets are unreachable.
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

#### Host
- **Fields**: `targets` (optional), `target_mode` (optional)
- **Behavior**: Sends a heartbeat signal confirming the agent is running.
- **Example**:
  ```yaml
  - name: "Local Health Check"
    type: "host"
    interval: "5m" # Required if the global `default_interval` is not set
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

#### WireGuard
Monitors a WireGuard VPN tunnel health via handshake timestamps. No external targets are required; health is determined by the most recent successful handshake with the peer.

- **Fields**: `tunnel` (required if `wireguard` block is not present), `wireguard:` block (required if `tunnel` is not present)
- **Validation Rules**:
  - **Exclusivity**: Exactly one of root-level `tunnel` OR an inline `wireguard:` block must be present.
  - **Type Safety**: If a root `tunnel` is referenced, it MUST be of type `wireguard`.
- **WireGuard Block**: `max_age` (required, e.g., "5m"), `restart_threshold` (optional, default 1), `endpoint`, `public_key`, `private_key`, `addresses`, `preshared_key` (optional), `allowed_ips` (optional), `persistent_keepalive` (optional)
- **Behavior**: 
  - Monitors the WireGuard handshake timestamp via the device interface
  - Reports success if handshake is within `max_age`
  - Triggers tunnel restart if handshake exceeds `max_age` (after stabilization phase)
  - See the [Tunnels](#tunnels) section for details on tunnel health tracking and restart logic

> [!WARNING]
> **Reliability Note**: The WireGuard "Heartbeat" check relies on the `latest_handshake` timestamp from the interface. Use this with caution, as it does not guarantee end-to-end connectivity.
>
> **Recommended Approach**: It is preferred to verify the tunnel by pairing it with another monitor (e.g., `ping`, `tcp`, or `http`) that routes traffic **through** the tunnel.
>
> Example:
> ```yaml
> - name: "VPN Connectivity"
>   type: "ping"
>   targets: ["10.0.0.1"] # Internal IP inside the VPN
>   tunnel: "office-vpn" # Route the ping through the tunnel
> ```

- **Example (using root tunnel)**:
  ```yaml
  - name: "Personal VPN Heartbeat"
    type: "wireguard"
    tunnel: "office-vpn" # Use the tunnel defined in the root tunnels block
    interval: "5m" # Required if the global `default_interval` is not set.
    wireguard:
      max_age: "5m" # Trigger failure if WireGuard tunnel handshake is older than this.
    monitor_endpoint:
      success:
        url: "https://uptime.test/api/push/vpn-ok"
  ```
- **Example (manual configuration)**:
  ```yaml
  - name: "Manual VPN"
    type: "wireguard"
    wireguard:
      endpoint: "vpn.example.local:51820"
      public_key: "PEER_PUBLIC_KEY"
      private_key: "YOUR_PRIVATE_KEY"
      addresses: "10.0.0.2/32"
      max_age: "5m" # Trigger failure if WireGuard tunnel handshake is older than this.
  ```


#### SSH
Monitors SSH connectivity and optionally performs authentication.
- **Fields**: `tunnel` (optional), `target` (optional), `ssh:` block (optional)
- **Bastion / Jump Host Pattern**: 
  - If both `tunnel` and `target` are present, the root `tunnel` acts as a transport (bastion) for the SSH check. This supports complex scenarios like **SSH-in-SSH** or **SSH-over-WireGuard**.
- **Validation Rules**:
  - At least one of `target` or `tunnel` must be present.
  - If only `tunnel` exists, the probe uses the tunnel's own configuration and target.
- **SSH Block**: `user` (required if `auth_required` is true), `password` (optional), `private_key` (optional), `auth_required` (optional, defaults to true), `port` (optional, defaults to 22), `timeout` (optional, defaults to 5s)

> [!TIP]
> **SSH Connection Caching**: Root `ssh` tunnels cache the underlying client connection. Before each reuse, a keepalive check is performed — if the connection is dead, the agent automatically closes and reconnects during the next probe cycle. Reporting a failure also forces a reconnect.

- **Example (using root tunnel)**:
  ```yaml
  - name: "Core Server SSH"
    type: "ssh"
    tunnel: "secure-ssh" # References a root ssh tunnel
    monitor_endpoint:
      success:
        url: "https://uptime.test/api/push/ssh-ok"
  ```

- **Example (manual configuration)**:
  ```yaml
  - name: "Remote Server SSH"
    type: "ssh"
    target: "ssh.example.com"
    interval: "5m"
    timeout: "5s" # Optional, defaults to 5s.
    ssh:
      user: "monitor"
      password: "secret-password"
      port: 2222
      auth_required: true
    monitor_endpoint:
      success:
        url: "https://uptime.test/api/push/ssh-ok"
  ```

#### Docker
- **Fields**: `tunnel` (optional), `targets` (**required** - container names), `docker:` block (**required**)
- **Validation Rules**:
  - **Tunnel Support**: If a `tunnel` is specified, the referenced `docker-socket` **must** be a proxied one (using `host`/`port`). Local Unix sockets cannot be used over a tunnel.
- **Docker Block**: `socket` (**required**), `healthy` (optional)
- **Example**:
  ```yaml
  - name: "Docker Service"
    type: "docker"
    interval: "5m" # Required if the global `default_interval` is not set
    targets: ["web-container"]
    timeout: "5s" # Optional, defaults to 5s.
    docker:
      socket: "local"
      healthy: true
    monitor_endpoint:
      success:
        url: "https://uptime.probixel.test/api/push/success?duration={%duration%}ms"
      failure: # Optional failure endpoint. Useful to send error messages to an alert endpoint.
        url: "https://uptime.probixel.test/api/push/failure?error={%error%}"
  ```

## Target Modes

When monitoring multiple targets, you can specify how success is determined:

- **`any`** (default): Succeeds if **any** target is reachable
- **`all`**: Succeeds only if **all** targets are reachable

```yaml
services:
  - name: "Load Balanced Service"
    type: "tcp"
    targets: ["lb1:80", "lb2:80", "lb3:80"]
    target_mode: "any"  # Success if at least one LB is up

  - name: "Cluster Nodes"
    type: "tcp"
    targets: ["node1:9000", "node2:9000", "node3:9000"]
    target_mode: "all"  # Success only if all nodes are up
```

> [!NOTE]
> **Automatic Trimming**: All probes automatically trim leading and trailing whitespace from target strings. For probes supporting multi-targets (DNS, Docker, Ping, TCP, UDP), each individual target in the comma-separated list is trimmed (e.g., `"8.8.8.8,  1.1.1.1"` is parsed correctly).
>
> **Target Mode Support**: The `target_mode` setting is only applicable to probes that support multiple targets (`DNS`, `Docker`, `Ping`, `TCP`, `TLS`, `UDP`). The `HTTP`, `Host`, `SSH`, and `WireGuard` probes do not support multi-targets or `target_mode` in a meaningful way.

## Interval Format

Intervals specify how often a probe check is performed. They support the following time units:
- `s` - seconds
- `m` - minutes
- `h` - hours
- `d` - days

Examples: `30s`, `5m`, `2h`, `1d`

The agent uses a hierarchy for intervals:
1. **Service Interval**: If a service specifies its own `interval`, this value is used.
2. **Global Default**: If a service does **not** specify an `interval`, the `global.default_interval` is used.
3. **Validation**: If neither value is provided, the configuration will fail to load.


> [!TIP]
> - **Interval Hierarchy**: Per-service intervals always override the global default.
> - **Insecure TLS**: If your alert endpoints use self-signed certificates (e.g., an internal Uptime Kuma instance), you can set `insecure_skip_verify: true` inside the `success` or `failure` block.
> - **Optional Failure Endpoints**: The `failure` alert endpoint is optional. If you omit it, no notification will be sent when a service fails. The `success` endpoint remains required.

## Alert Endpoints

The agent sends HTTP requests to configured endpoints. You must use **template variables** in your URLs to include monitoring data.

### URL Template Variables

Template variables allow you to customize how monitoring data is included in alert URLs:

- `{%duration%}` - Probe duration in milliseconds
- `{%error%}` - Error message (empty string on success)
- `{%message%}` - Result message (always available)
- `{%target%}` - Target that was checked
- `{%timestamp%}` - Unix timestamp
- `{%success%}` - "true" or "false"

Example: 
```yaml
monitor_endpoint:
  success:
    url: "https://uptime.probixel.test/api/push/success?duration={%duration%}&message={%message%}&target={%target%}&timestamp={%timestamp%}&success={%success%}"
```

**Important**: Template variables are **required** to pass monitoring data. URLs without template variables will not automatically include duration or error information.

> [!IMPORTANT]
> **Header Isolation**: The headers defined for the **HTTP Probe** (under the service root) are completely isolated from the **Alert headers** (under `monitor_endpoint`). This ensures that probe credentials (like API keys) are never sent to your alert/webhook provider.

**Note**: The global `monitor_endpoint` supports `headers`, `timeout`, and `retries` fields. Each success and failure URL (optional) must be configured at the service level.

### HTTP Methods

Default method is `GET`. You can specify custom methods:

```yaml
monitor_endpoint:
  success:
    url: "https://api.example.com/webhook?d={%duration%}"
    method: "PUT"
    headers:
      Content-Type: "application/json"
```

### Timeout Hierarchy

Monitor endpoint timeouts follow a hierarchy of precedence:
1. **Endpoint-specific**: `timeout` defined inside a `success` or `failure` block.
2. **Service-level**: `timeout` defined inside the `monitor_endpoint` block of a service.
3. **Global**: `timeout` defined in the `global.monitor_endpoint` block.
4. **Default**: `5s` if no timeout is specified anywhere.

This allows you to set a conservative global timeout while allowing specific slow endpoints (e.g., a webhook that triggers a heavy process) to have a longer timeout.

## Development

### Makefile Targets

The `Makefile` provides convenient shortcuts for common development tasks:

| Target | Description |
|---|---|
| `make help` | Show available targets |
| `make test` | Run all Go tests |
| `make lint` | Run `golangci-lint` |
| `make build-native` | Build native binary |
| `make run-native` | Run native binary |
| `make build` | Build Docker image |
| `make build-arm64` | Build for ARM64 |
| `make build-multi` | Multi-arch build (amd64, arm64, arm/v7) |
| `make run` | Run container with Docker CLI |
| `make up` / `make down` | Docker Compose lifecycle |
| `make logs` | View container logs |
| `make restart` / `make stop` | Container management |
| `make shell` / `make stats` | Debug utilities |
| `make clean` | Remove unused Docker images |

### Running Tests Manually

```bash
# Run all tests
go test -v ./...

# Run with race detection (as CI does)
go test -race -count=3 ./...

# Run specific package tests
go test -v ./pkg/monitor/...

# Run integration tests
go test -v ./cmd/...
```

### Project Structure

```
.
├── cmd/                    # Entry point (main.go) and integration tests
├── pkg/
│   ├── agent/              # Service monitor loop, probe factory, thread-safe config state
│   ├── config/             # YAML config parsing, validation, duration helpers
│   ├── health/             # PID file management and health checks
│   ├── monitor/            # 10 probe implementations (HTTP, TCP, UDP, DNS, Ping, Host, Docker, WireGuard, TLS, SSH)
│   ├── notifier/           # Alert push logic with rate limiting and template variables
│   ├── tunnels/            # WireGuard and SSH tunnel transports + mock
│   └── watchdog/           # File watcher, config reload, component lifecycle
├── docker/                 # Dockerfile, docker-compose, DOCKER.md, helper script
├── .github/workflows/      # CI (test + lint + build) and Release (multi-arch Docker + GitHub Release)
├── Makefile                # Build, test, lint, and container management shortcuts
└── config.example.yaml     # Annotated example configuration
```

## CI/CD

This project uses GitHub Actions for continuous integration and deployment.

### Test Pipeline (`test.yml`) — runs on every push and PR

| Job | Details |
|---|---|
| **Test** | `go test -race -count=3`, enforces **96% coverage** threshold, generates a coverage badge, and auto-creates a PR for it |
| **Lint** | `go vet` + `staticcheck` + `golangci-lint` |
| **Build** | Compiles binary and uploads artifact |

### Release Pipeline (`release.yml`) — manual trigger via `workflow_dispatch`

| Step | Details |
|---|---|
| **Versioning** | Semantic version bump (`patch`, `minor`, `major`) with automatic tag creation |
| **Docker Build** | Multi-arch (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) using native Go cross-compilation |
| **Registry Push** | Docker Hub (`kfalabs/probixel`) + GHCR (`ghcr.io/kfalabs/probixel`) |
| **GitHub Release** | Auto-generated release notes |

### Docker Builds

For detailed Docker usage, configuration options, and deployment examples, see [DOCKER.md](docker/DOCKER.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
