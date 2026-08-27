# Probixel

Probixel is a Go monitoring agent. It reads YAML configuration, runs service probes, sends status notifications, and supports SSH and WireGuard tunnels.

The required Go toolchain is Go **1.27.0**. Keep `go.mod`, Docker, CI workflows, local commands, and documentation aligned with that version.

- `cmd/`: application entry point.
- `pkg/config/`: configuration parsing and validation.
- `pkg/monitor/`: probe implementations.
- `pkg/tunnels/`: tunnel lifecycle and dialers.
- `pkg/agent/`: probe setup and monitoring loops.
- `pkg/watchdog/`: application lifecycle and config reloads.
- `pkg/notifier/`: alert delivery and rate limiting.
- `pkg/health/`: process health endpoint support.

## Probes

Service `type` values are:

- `http`: HTTP/HTTPS status and response checks.
- `tcp`: TCP connection checks.
- `udp`: UDP reachability checks.
- `dns`: DNS lookups.
- `ping`: ICMP ping checks.
- `host`: host-level heartbeat checks.
- `docker`: Docker container status and health checks.
- `tls`: TLS connectivity and certificate-expiry checks.
- `ssh`: SSH connectivity and authentication checks.
- `wireguard`: WireGuard handshake heartbeat checks.

Multiple targets use `target_mode: any` by default, or `all` when every target must pass. Services can route supported probes through a named root tunnel.

## Tunnels and runtime

- Root tunnel types are `ssh` and `wireguard`; their lifecycle belongs in `pkg/tunnels`.
- WireGuard tunnels use a stabilization period and a background supervisor; preserve recovery behavior and fail closed when a configured tunnel is unavailable.
- The watchdog initializes tunnels, creates probes, starts monitoring loops, and reloads YAML configuration changes.
- Configuration validation belongs in `pkg/config`; service-specific setup belongs in `pkg/agent`.

## Runtime flow

- `cmd` loads configuration and starts the watchdog.
- The watchdog owns active configuration, the tunnel registry, notifier, config watcher, and monitoring lifecycle.
- On startup or reload, it stops old tunnels, creates and registers root tunnels, sets up probes, and starts service monitors.
- `agent.SetupProbe` applies service configuration to a concrete probe and attaches a named tunnel when configured.
- `agent.RunServiceMonitor` uses the service interval or `global.default_interval`.
- Probe results are sent through the notifier according to configured success and failure monitor endpoints.
- Reload cancels monitoring contexts before their replacements start.
- In `monitor.Result`, `Success` means passing and `Pending` is only for temporary initialization or stabilization. Never hide permanent failures with `Pending`.

## Probe implementation patterns

- Use `pkg/monitor/<name>_probe.go` with matching `*_probe_test.go` tests.
- A new probe implements `monitor.Probe`, is added to `monitor.GetProbe`, has config validation, and gets focused tests.
- HTTP owns response, header, body-match, and HTTP TLS behavior; TLS owns connectivity and certificate expiry.
- Docker probes use configured Docker sockets and should not duplicate generic HTTP behavior.
- WireGuard probes are handshake heartbeats, not generic transport probes.
- Probes measure checks and return results; notification policy belongs in `pkg/notifier` and `pkg/agent`.
- `target_mode: any` means one target succeeds; `all` means every target succeeds.
- Close all created response bodies, raw connections, sessions, and sockets.

## Tunnel lifecycle patterns

- `tunnels.Tunnel` is the shared interface; `tunnels.Registry` is the source of truth for named root tunnels.
- Services configured with a tunnel fail closed when it is unavailable; never bypass it by dialing directly.
- Register a tunnel when its supervisor can recover transient initialization failures.
- The watchdog owns root WireGuard tunnels; an inline WireGuard probe owns its ephemeral tunnel. A probe never stops a root tunnel.
- WireGuard supervision must be independent of probe traffic so ping, UDP, and DNS topology cannot starve recovery.
- Restart only when both handshake and recent service-success signals are stale.
- Resolve hostname endpoints with a bounded context outside the write lock; reuse the last good endpoint during a transient DNS outage.
- Refresh initialization time after device replacement and honor stabilization.
- Start and stop supervisors with their owner lifecycle so a stopped component cannot recreate resources.

## Conventions

- Use TDD: write or update a focused failing test first, then implement the smallest change that makes it pass.
- Keep behavior covered by tests; add regression tests for bugs.
- Follow standard Go style and run `gofmt` on changed Go files.
- Keep package boundaries clear: configuration in `config`, probe behavior in `monitor`, transport lifecycle in `tunnels`.
- Use context-aware I/O and clean up goroutines, timers, connections, and tunnel resources.
- Preserve unrelated working-tree changes.

## TDD workflow

- TDD is required for bug fixes and behavior changes.
- Start with the smallest focused test that demonstrates the desired behavior or regression.
- Run it and confirm it fails for the expected reason before changing production code.
- Make the smallest clear change that passes; refactor only after it passes, and keep the regression test.
- Prefer deterministic tests over real network calls, DNS dependencies, or long sleeps.
- Use existing seams such as device factories, mocks, package-level lifecycle factories, and injectable timing values.
- For goroutine behavior, use bounded eventual assertions with short polling and a deadline; never use unbounded waits or production-scale timeouts.
- Keep helpers local unless they are genuinely shared infrastructure.

## Configuration conventions

- Configuration parsing, defaults, and validation belong in `pkg/config`.
- Use `config.ParseDuration` for config duration fields rather than direct `time.ParseDuration` calls.
- Validate required fields in `Config.Validate` and test both accepted and rejected configurations.
- When behavior changes, align struct tags, validation, defaults, `config.example.yaml`, README documentation, and tests.
- Do not change defaults unless requested; they are part of the public contract.
- Use the effective interval, including `global.default_interval`, for retry and health-window calculations.

## Go and concurrency conventions

- Run `gofmt` on every changed Go file and use normal Go naming and `%w` error wrapping.
- Pass `context.Context` to blocking operations and honor cancellation promptly.
- Keep mutex critical sections short; never hold one across DNS resolution, device IPC, dialing, or blocking work.
- For read-then-act changes, snapshot under lock, do blocking work outside it, then reacquire and verify the snapshot still applies.
- Avoid lock-order inversions between registries, tunnels, and supervisor state.
- Every owned goroutine needs a stop signal; wait during teardown when it could recreate resources after shutdown.
- Race tests cover test hooks and mocks. Synchronize shared test state.
- Stop timers that will not fire.

## Logging and notifications

- Notifier delivery, endpoint headers, retries, templates, and rate limiting belong in `pkg/notifier`.
- Probes do not make direct notification HTTP calls.
- Log lifecycle transitions, actionable failures, and recoveries with an identifying service or tunnel name.
- Avoid logs on every healthy poll or repeated retry attempt; use state-transition logging for recovery loops.

## Change discipline

- Keep changes scoped to the request.
- Preserve unrelated working-tree changes; do not reset, checkout, or delete them.
- Do not use destructive Git commands unless explicitly asked.
- Add or update tests whenever observable behavior changes.
- Explain necessary interface, lifecycle, or test-seam additions in the handoff.

## Verification

Run before handing off:

```sh
go test ./...
go test ./... -race -count=3
go vet ./...
```
