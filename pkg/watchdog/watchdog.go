package watchdog

import (
	"context"
	"log"
	"sync"
	"time"

	"probixel/pkg/agent"
	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/notifier"
	"probixel/pkg/tunnels"

	"github.com/fsnotify/fsnotify"
)

// ReloadDelay is the time to wait after a config file modification before reloading.
// This can be set to a shorter duration in tests.
var ReloadDelay = 10 * time.Second

// StartingWindow is the duration at startup/reload during which the application stabilizes.
// This can be set to 0 in tests to prevent delays.
var StartingWindow = 10 * time.Second

// Watchdog manages the agent lifecycle, configuration reloads, and service monitors.
type Watchdog struct {
	configPath     string
	shared         *agent.ConfigState
	tunnelRegistry *tunnels.Registry
	pusher         *notifier.Pusher
	reloadChan     chan struct{}

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup

	monitorCancel context.CancelFunc
	monitorWg     sync.WaitGroup
}

func NewWatchdog(configPath string, cfg *config.Config) *Watchdog {
	return &Watchdog{
		configPath:     configPath,
		shared:         agent.NewConfigState(cfg),
		tunnelRegistry: tunnels.NewRegistry(),
		pusher:         notifier.NewPusher(),
		reloadChan:     make(chan struct{}, 1),
	}
}

func (w *Watchdog) Start(ctx context.Context) {
	w.mu.Lock()
	ctx, w.cancel = context.WithCancel(ctx)
	w.mu.Unlock()
	w.pusher.SetRateLimit(w.shared.Get().Global.Notifier.RateLimit)

	// Start config watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create file watcher: %v", err)
	} else {
		err = watcher.Add(w.configPath)
		if err != nil {
			log.Printf("Failed to watch config file: %v", err)
			_ = watcher.Close()
		} else {
			w.wg.Add(1)
			go w.watchConfigFile(ctx, watcher)
		}
	}

	w.wg.Add(1)
	go w.run(ctx)
}

func (w *Watchdog) run(ctx context.Context) {
	defer w.wg.Done()

	for {
		// New monitoring context for this configuration run
		monitorCtx, monitorCancel := context.WithCancel(ctx)
		w.monitorCancel = monitorCancel
		w.monitorWg = sync.WaitGroup{}

		currentCfg := w.shared.Get()

		// Phase 0: Initialize root-level tunnels
		// Stop any existing tunnels from previous run
		w.tunnelRegistry.StopAll()

		for name, tCfg := range currentCfg.Tunnels {
			var t tunnels.Tunnel
			switch tCfg.Type {
			case "wireguard":
				if tCfg.Wireguard != nil {
					t = tunnels.NewWireguardTunnel(name, tCfg.Wireguard)
				}
			case "ssh":
				if tCfg.SSH != nil {
					t = tunnels.NewSSHTunnel(name, tCfg.Target, tCfg.SSH)
				}
			}

			if t != nil {
				if err := t.Initialize(); err != nil {
					log.Printf("[Tunnel:%s] Failed to initialize: %v", name, err)
				} else {
					log.Printf("[Tunnel:%s] Initialized", name)
				}
				_ = w.tunnelRegistry.Register(t)
			}
		}

		// Calculate and set success window for WireGuard tunnels
		agent.SetupWireguardWindows(currentCfg, w.tunnelRegistry)

		// Initialize all probes
		type serviceProbe struct {
			svc   config.Service
			probe monitor.Probe
		}
		var serviceProbes []serviceProbe

		for _, svc := range currentCfg.Services {
			probe, err := agent.SetupProbe(svc, currentCfg, w.tunnelRegistry)
			if err != nil {
				log.Printf("[%s] Failed to setup probe: %v. Service will be skipped.", svc.Name, err)
				continue
			}
			serviceProbes = append(serviceProbes, serviceProbe{svc: svc, probe: probe})
		}

		// Start all service monitors
		if StartingWindow > 0 {
			log.Printf("Waiting %v for application to start...", StartingWindow)
			time.Sleep(StartingWindow)
		}
		for _, sp := range serviceProbes {
			w.monitorWg.Add(1)
			go agent.RunServiceMonitor(monitorCtx, sp.svc, sp.probe, w.shared, w.tunnelRegistry, w.pusher, &w.monitorWg)
		}

		log.Printf("Agent components started with %d services", len(serviceProbes))

		// Wait for reload or shutdown
		select {
		case <-ctx.Done():
			w.monitorCancel()
			w.monitorWg.Wait()
			return
		case <-w.reloadChan:
			log.Println("Restarting monitors with new configuration...")
			w.monitorCancel()
			w.monitorWg.Wait()
		}
	}
}

func (w *Watchdog) watchConfigFile(ctx context.Context, watcher *fsnotify.Watcher) {
	defer w.wg.Done()
	defer func() { _ = watcher.Close() }()

	var (
		timer     *time.Timer
		timerChan <-chan time.Time
	)

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file modified, scheduling reload in %v...", ReloadDelay)
				if timer != nil {
					timer.Stop()
				}
				timer = time.NewTimer(ReloadDelay)
				timerChan = timer.C
			}
		case <-timerChan:
			timerChan = nil // Reset timer chan
			newCfg, err := config.LoadConfig(w.configPath)
			if err != nil {
				log.Printf("Failed to reload config: %v. Keeping old configuration.", err)
			} else {
				w.shared.Set(newCfg)
				w.pusher.SetRateLimit(newCfg.Global.Notifier.RateLimit)
				log.Printf("Config reloaded successfully with %d services", len(newCfg.Services))

				select {
				case w.reloadChan <- struct{}{}:
				default:
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error: %v", err)
		}
	}
}

func (w *Watchdog) Stop() {
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	w.wg.Wait()
	w.tunnelRegistry.StopAll()
}
