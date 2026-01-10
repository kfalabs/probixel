package agent

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/notifier"
	"probixel/pkg/tunnels"
)

func RunServiceMonitor(ctx context.Context, svc config.Service, probe monitor.Probe, state *ConfigState, registry *tunnels.Registry, pusher *notifier.Pusher, wg *sync.WaitGroup) {
	defer wg.Done()

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

	result, err := probe.Check(ctx, target)
	if err != nil {
		log.Printf("[%s] Probe internal error: %v", svc.Name, err)
		return
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

	if err := pusher.Push(result, svc.MonitorEndpoint, cfg.Global.MonitorEndpoint); err != nil {
		log.Printf("[%s] Failed to push alert: %v", svc.Name, err)
	}
}
