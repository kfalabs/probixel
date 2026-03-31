package agent

import (
	"context"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/notifier"
	"probixel/pkg/tunnels"
)

// RetryBackoff is the base delay between probe retries. Exported for test override.
var RetryBackoff = 5 * time.Second

func RunServiceMonitor(ctx context.Context, svc config.Service, probe monitor.Probe, state *ConfigState, registry *tunnels.Registry, pusher *notifier.Pusher, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] [PANIC] RunServiceMonitor: %v\n%s", svc.Name, r, debug.Stack())
		}
	}()

	intervalStr := svc.Interval
	if intervalStr == "" {
		intervalStr = state.Get().Global.DefaultInterval
	}

	duration, err := config.ParseDuration(intervalStr)
	if err != nil {
		log.Printf("[%s] Invalid interval %q: %v", svc.Name, intervalStr, err)
		return
	}

	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	var checkMu sync.Mutex
	var checkCancel context.CancelFunc

	runCheck := func() {
		checkMu.Lock()
		if checkCancel != nil {
			checkCancel()
		}
		checkCtx, cancel := context.WithCancel(ctx)
		checkCancel = cancel
		checkMu.Unlock()
		CheckAndPush(checkCtx, probe, svc.Name, state, registry, pusher)
	}

	// First check
	runCheck()

	for {
		select {
		case <-ctx.Done():
			checkMu.Lock()
			if checkCancel != nil {
				checkCancel()
			}
			checkMu.Unlock()
			return
		case <-ticker.C:
			runCheck()
		}
	}
}

func CheckAndPush(ctx context.Context, probe monitor.Probe, serviceName string, state *ConfigState, registry *tunnels.Registry, pusher *notifier.Pusher) {
	cfg := state.Get()
	var svc *config.Service
	for i := range cfg.Services {
		if cfg.Services[i].Name == serviceName {
			svc = &cfg.Services[i]
			break
		}
	}

	if svc == nil {
		return
	}

	target := svc.Target
	if target == "" {
		target = svc.URL
	}
	if target == "" && len(svc.Targets) > 0 {
		target = strings.Join(svc.Targets, ",")
	}

	// Determine effective probe retries
	retries := 3
	if cfg.Global.Monitor.Retries != nil {
		retries = *cfg.Global.Monitor.Retries
	}
	if svc.Retries != nil {
		retries = *svc.Retries
	}
	// Exempt host and wireguard probes
	if svc.Type == "host" || svc.Type == "wireguard" {
		retries = 0
	}

	var result monitor.Result
	var lastErr error

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			// Backoff before retry to span WireGuard handshake windows
			backoff := time.Duration(attempt) * RetryBackoff
			log.Printf("[%s] Retrying probe check (attempt %d/%d) after %v...", svc.Name, attempt, retries, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
		}

		result, lastErr = probe.Check(ctx, target)
		if lastErr == nil && !result.Pending && result.Success {
			// Success!
			break
		}
		if lastErr != nil {
			log.Printf("[%s] Probe internal error: %v", svc.Name, lastErr)
		}
		if !result.Success && !result.Pending && attempt < retries {
			// Failed but have retries left
			continue
		}
		// Either success, pending, or out of retries
		break
	}

	if lastErr != nil && result.Message == "" {
		result.Message = lastErr.Error()
	}

	if result.Success && svc.Tunnel != "" {
		if tunnel, ok := registry.Get(svc.Tunnel); ok {
			tunnel.ReportSuccess()
		}
	}

	status := "DOWN"
	if result.Pending {
		status = "WAITING"
	} else if result.Success {
		status = "UP"
	}
	log.Printf("[%s] %s (%s) %v", svc.Name, status, result.Message, result.Duration)

	if err := pusher.Push(ctx, svc.Name, result, svc.MonitorEndpoint, cfg.Global.MonitorEndpoint); err != nil {
		log.Printf("[%s] Failed to push alert: %v", svc.Name, err)
	}
}
