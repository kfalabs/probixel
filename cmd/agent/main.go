package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/notifier"

	"github.com/fsnotify/fsnotify"
)

// sharedConfig holds the configuration with thread-safe access
type sharedConfig struct {
	mu     sync.RWMutex
	config *config.Config
}

func (sc *sharedConfig) get() *config.Config {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.config
}

func (sc *sharedConfig) set(cfg *config.Config) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.config = cfg
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	pidFile := flag.String("pidfile", "/tmp/probixel.pid", "Path to PID file")
	healthCheck := flag.Bool("health", false, "Perform health check and exit")
	initDelay := flag.Int("delay", 10, "Initialization delay in seconds (0 to disable)")
	flag.Parse()

	if *healthCheck {
		checkHealth(*pidFile)
	}

	// Write PID file
	if err := writePIDFile(*pidFile); err != nil {
		log.Fatalf("Failed to write PID file: %v", err)
	}
	defer func() { _ = os.Remove(*pidFile) }()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create shared config
	shared := &sharedConfig{config: cfg}

	pusher := notifier.NewPusher()
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, stopping agents...")
		cancel()
	}()

	// Start config file watcher
	reloadChan := make(chan struct{}, 1)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create file watcher: %v", err)
	} else {
		defer func() { _ = watcher.Close() }()
		err = watcher.Add(*configPath)
		if err != nil {
			log.Printf("Failed to watch config file: %v", err)
		} else {
			wg.Add(1)
			go watchConfigFile(ctx, &wg, watcher, *configPath, shared, reloadChan)
		}
	}

	for {
		// New monitoring context for this configuration run
		monitorCtx, monitorCancel := context.WithCancel(ctx)
		var monitorWg sync.WaitGroup

		currentCfg := shared.get()

		// Phase 1: Initialize all probes
		type serviceProbe struct {
			svc   config.Service
			probe monitor.Probe
		}
		var serviceProbes []serviceProbe

		for _, svc := range currentCfg.Services {
			probe, err := setupProbe(svc, currentCfg)
			if err != nil {
				log.Printf("[%s] Failed to setup probe: %v. Service will be skipped.", svc.Name, err)
				continue
			}

			// Early initialization (e.g. WireGuard tunnels)
			if init, ok := probe.(monitor.Initializer); ok {
				if err := init.Initialize(); err != nil {
					log.Printf("[%s] Warning: early initialization failed: %v", svc.Name, err)
				}
			}

			serviceProbes = append(serviceProbes, serviceProbe{svc: svc, probe: probe})
		}

		// Phase 2: Global initialization delay
		if *initDelay > 0 && len(serviceProbes) > 0 {
			log.Printf("Waiting %ds for services to initialize...", *initDelay)

			// Wait with cancel support
			select {
			case <-time.After(time.Duration(*initDelay) * time.Second):
			case <-monitorCtx.Done():
				monitorCancel()
				goto cleanup
			}
		}

		// Phase 3: Start all service monitors
		for _, sp := range serviceProbes {
			monitorWg.Add(1)
			go runServiceMonitor(monitorCtx, &monitorWg, sp.svc, sp.probe, pusher, shared)
		}

		log.Printf("Agent started with %d services", len(serviceProbes))

		// Wait for reload or shutdown
		select {
		case <-ctx.Done():
			monitorCancel()
			monitorWg.Wait()
			goto cleanup
		case <-reloadChan:
			log.Println("Restarting monitors with new configuration...")
			monitorCancel()
			monitorWg.Wait()
			// Continue loop to restart
		}
	}

cleanup:
	wg.Wait()
	log.Println("Agent stopped.")
}

func writePIDFile(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(strconv.Itoa(pid)), 0600)
}

func checkHealth(pidFile string) {
	data, err := os.ReadFile(pidFile) //nolint:gosec // G304: Reading internal PID file
	if err != nil {
		fmt.Printf("Health check failed: could not read PID file: %v\n", err)
		os.Exit(1)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Printf("Health check failed: invalid PID in file: %v\n", err)
		os.Exit(1)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("Health check failed: could not find process %d: %v\n", pid, err)
		os.Exit(1)
	}

	// On Unix, FindProcess always succeeds. Use signal 0 to check if process exists.
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		fmt.Printf("Health check failed: process %d is not running: %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("Health check passed: process %d is running\n", pid)
	os.Exit(0)
}

// watchConfigFile watches for config file changes and reloads configuration
func watchConfigFile(ctx context.Context, wg *sync.WaitGroup, watcher *fsnotify.Watcher, configPath string, shared *sharedConfig, reloadChan chan struct{}) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file modified, reloading...")
				// Small delay to ensure file write is complete
				time.Sleep(200 * time.Millisecond)
				newCfg, err := config.LoadConfig(configPath)
				if err != nil {
					log.Printf("Failed to reload config: %v. Keeping old configuration.", err)
				} else {
					shared.set(newCfg)
					log.Printf("Config reloaded successfully with %d services", len(newCfg.Services))

					select {
					case reloadChan <- struct{}{}:
					default:
					}
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

func setupProbe(svc config.Service, cfg *config.Config) (monitor.Probe, error) {
	probe, err := monitor.GetProbe(svc.Type)
	if err != nil {
		return nil, err
	}

	switch p := probe.(type) {
	case *monitor.HTTPProbe:
		if svc.HTTP != nil {
			p.Method = svc.HTTP.Method
			p.Headers = svc.HTTP.Headers
			p.AcceptedStatusCodes = svc.HTTP.AcceptedStatusCodes
			p.InsecureSkipVerify = svc.HTTP.InsecureSkipVerify
			p.MatchData = svc.HTTP.MatchData
			if svc.HTTP.CertificateExpiry != "" {
				d, err := config.ParseDuration(svc.HTTP.CertificateExpiry)
				if err != nil {
					return nil, fmt.Errorf("invalid certificate_expiry for service %q: %w", svc.Name, err)
				}
				p.ExpiryThreshold = d
			}
		}
		// Set default method if empty
		if p.Method == "" {
			p.Method = "GET"
		}
	case *monitor.DNSProbe:
		if svc.DNS != nil {
			p.SetDomain(svc.DNS.Domain)
		}
	}

	// Configure TLS probe
	if tlsProbe, ok := probe.(*monitor.TLSProbe); ok && svc.TLS != nil {
		if svc.TLS.CertificateExpiry != "" {
			if dur, err := config.ParseDuration(svc.TLS.CertificateExpiry); err == nil {
				tlsProbe.ExpiryThreshold = dur
			}
		}
		tlsProbe.InsecureSkipVerify = svc.TLS.InsecureSkipVerify
	}

	// Configure Docker probe
	if dockerProbe, ok := probe.(*monitor.DockerProbe); ok && svc.Docker != nil {
		dockerProbe.Sockets = cfg.DockerSockets
		dockerProbe.SocketName = svc.Docker.Socket
		dockerProbe.Healthy = svc.Docker.Healthy
	}

	// Configure Wireguard probe
	if wgProbe, ok := probe.(*monitor.WireguardProbe); ok && svc.Wireguard != nil {
		wgProbe.Config = svc.Wireguard
	}

	// Resolve target mode
	targetMode := monitor.TargetModeAny
	if svc.TargetMode != "" {
		targetMode = svc.TargetMode
	}
	probe.SetTargetMode(targetMode)

	return probe, nil
}

func runServiceMonitor(ctx context.Context, wg *sync.WaitGroup, svc config.Service, probe monitor.Probe, pusher *notifier.Pusher, shared *sharedConfig) {
	defer wg.Done()

	intervalStr := svc.Interval
	if intervalStr == "" {
		intervalStr = shared.get().Global.DefaultInterval
	}

	duration, err := config.ParseDuration(intervalStr)
	if err != nil {
		// This should theoretically not happen as the config is validated at load time.
		log.Printf("[%s] Invalid interval %q: %v", svc.Name, intervalStr, err)
		return
	}

	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	// Perform first check immediately after global delay
	checkAndPush(ctx, probe, svc.Name, shared, pusher)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndPush(ctx, probe, svc.Name, shared, pusher)
		}
	}
}

func checkAndPush(ctx context.Context, probe monitor.Probe, serviceName string, shared *sharedConfig, pusher *notifier.Pusher) {
	// Read latest config
	cfg := shared.get()

	// Find this service in the config
	var svc *config.Service
	for i := range cfg.Services {
		if cfg.Services[i].Name == serviceName {
			svc = &cfg.Services[i]
			break
		}
	}

	if svc == nil {
		log.Printf("[%s] Service not found in config, skipping check", serviceName)
		return
	}

	// Resolve target
	target := svc.URL
	if target == "" && len(svc.Targets) > 0 {
		target = strings.Join(svc.Targets, ",")
	}

	result, err := probe.Check(ctx, target)
	if err != nil {
		log.Printf("[%s] Probe internal error: %v", svc.Name, err)
		return
	}

	status := "DOWN"
	if result.Success {
		status = "UP"
	}
	log.Printf("[%s] %s (%s) %v", svc.Name, status, result.Message, result.Duration)

	if err := pusher.Push(result, svc.MonitorEndpoint, cfg.Global.MonitorEndpoint); err != nil {
		log.Printf("[%s] Failed to push alert: %v", svc.Name, err)
	}
}
