package watchdog

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"probixel/pkg/agent"
	"probixel/pkg/config"
)

func TestWatchdog_Lifecycle(t *testing.T) {
	// Create minimal valid config
	configFile, err := os.CreateTemp("", "lifecycle_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	cfgStr := `
global:
  interval: "1s"
services:
  - name: "Lifecycle Test"
    type: "host"
    target: "localhost"
    interval: "1s"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	if err := configFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load config first (required by NewWatchdog)
	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configFile.Name(), cfg)

	// Start in a goroutine
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	// Update config to trigger reload (optional, but good for coverage)
	// Just verify Stop works cleanly
	wd.Stop()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop within timeout")
	}
}

func TestConfigReload_Integration(t *testing.T) {
	// Create channels to track alerts
	alertMu := sync.Mutex{}
	receivedAlerts := []string{}

	// Create mock alert server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		alertMu.Lock()
		receivedAlerts = append(receivedAlerts, path)
		alertMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a UDP listener for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpConn.Close() }()
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	// Create temporary config file
	configFile, err := os.CreateTemp("", "reload_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	// Initial config with 300ms interval
	initialConfig := fmt.Sprintf(`
global:
  notifier:
    rate_limit: "0"

services:
  - name: "Test UDP Service"
    type: "udp"
    interval: "300ms"
    timeout: "100ms"
    targets: ["127.0.0.1:%d"]
    target_mode: "any"
    udp: {}
    monitor_endpoint:
      success:
        url: "%s/alert/initial?duration={%%duration%%}"
`, udpPort, ts.URL)

	if _, err := configFile.Write([]byte(initialConfig)); err != nil {
		t.Fatal(err)
	}
	if err := configFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load initial config
	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load initial config: %v", err)
	}

	// Create shared config
	shared := agent.NewConfigState(cfg)

	// Verify initial config
	if len(cfg.Services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(cfg.Services))
	}
	if cfg.Services[0].Name != "Test UDP Service" {
		t.Errorf("Expected service name 'Test UDP Service', got %s", cfg.Services[0].Name)
	}

	// Wait a bit
	time.Sleep(500 * time.Millisecond)

	// Update config with new alert URL
	updatedConfig := fmt.Sprintf(`
services:
  - name: "Test UDP Service"
    type: "udp"
    interval: "300ms"
    timeout: "100ms"
    targets: ["127.0.0.1:%d"]
    target_mode: "any"
    udp: {}
    monitor_endpoint:
      success:
        url: "%s/alert/updated?duration={%%duration%%}"
`, udpPort, ts.URL)

	// Write updated config
	if err := os.WriteFile(configFile.Name(), []byte(updatedConfig), 0644); err != nil { //nolint:gosec // G306: Test file permissions
		t.Fatal(err)
	}

	// Simulate config reload (what the watcher would do)
	time.Sleep(100 * time.Millisecond)
	newCfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	// Update shared config
	shared.Set(newCfg)

	// Verify config was updated
	reloadedCfg := shared.Get()
	if len(reloadedCfg.Services) != 1 {
		t.Fatalf("Expected 1 service after reload, got %d", len(reloadedCfg.Services))
	}

	// Verify the URL changed
	if reloadedCfg.Services[0].MonitorEndpoint.Success.URL != fmt.Sprintf("%s/alert/updated?duration={%%duration%%}", ts.URL) {
		t.Errorf("Config was not properly reloaded. Expected updated URL, got: %s",
			reloadedCfg.Services[0].MonitorEndpoint.Success.URL)
	}

	t.Log("Config reload test passed - configuration was successfully updated")
}

func TestWatchdog_WithSSHTunnel(t *testing.T) {
	configFile, err := os.CreateTemp("", "ssh_tunnel_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	cfgStr := `
global:
  default_interval: "1s"
tunnels:
  ssh-tun:
    type: ssh
    target: localhost
    ssh:
      user: testuser
      password: testpass
services:
  - name: "SSH Tunnel Test"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configFile.Name(), cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_WithWireguardTunnel(t *testing.T) {
	configFile, err := os.CreateTemp("", "wg_tunnel_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	cfgStr := `
global:
  default_interval: "1s"
tunnels:
  wg-tun:
    type: wireguard
    wireguard:
      endpoint: "1.2.3.4:51820"
      public_key: "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0="
      private_key: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU="
      addresses: "10.0.0.1/32"
services:
  - name: "WG Tunnel Test"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configFile.Name(), cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_ReloadTrigger(t *testing.T) {
	configFile, err := os.CreateTemp("", "reload_trigger_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	cfgStr := `
global:
  default_interval: "100ms"
services:
  - name: "Reload Test"
    type: "host"
    interval: "100ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configFile.Name(), cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	// Let it start
	time.Sleep(50 * time.Millisecond)

	// Trigger a manual reload
	select {
	case wd.reloadChan <- struct{}{}:
	default:
	}

	// Let it process
	time.Sleep(50 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop after reload")
	}
}

func TestWatchdog_StopBeforeStart(t *testing.T) {
	cfg := &config.Config{}
	wd := NewWatchdog("", cfg)
	// Should not panic
	wd.Stop()
}

func TestWatchdog_FailedProbeSetup(t *testing.T) {
	// Construct config manually to bypass Validate() and trigger SetupProbe error
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Services: []config.Service{
			{
				Name: "Unknown Probe Type",
				Type: "unknown-type", // Validated by LoadConfig, but injected directly
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
			{
				Name:     "Valid Service",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy_path.yaml", cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_StartWithNonExistentConfigPath(t *testing.T) {
	// Test the watcher.Add failure path (line 53-55)
	cfg := &config.Config{
		Services: []config.Service{
			{
				Name:     "Test",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	// Use a non-existent path to trigger watcher.Add failure
	wd := NewWatchdog("/nonexistent/path/to/config.yaml", cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	wd.Stop()

	select {
	case <-done:
		// Success - watcher.Add failed gracefully
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop after watcher failure")
	}
}

func TestWatchdog_StartWithRateLimit(t *testing.T) {
	configFile, err := os.CreateTemp("", "ratelimit_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	cfgStr := `
global:
  default_interval: "100ms"
  notifier:
    rate_limit: "1s"
services:
  - name: "Rate Limited Service"
    type: "host"
    interval: "100ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configFile.Name(), cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_ConfigFileModification(t *testing.T) {
	configFile, err := os.CreateTemp("", "modify_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Initial Service"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	// Let it start
	time.Sleep(100 * time.Millisecond)

	// Modify the file to trigger the write event
	newCfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Modified Service"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(newCfgStr, MockAlertServerURL)), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait a bit for the write event to be detected
	time.Sleep(200 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop after config modification")
	}
}

func TestWatchdog_ConfigFileInvalidOnReload(t *testing.T) {
	// Create initial valid config
	configFile, err := os.CreateTemp("", "invalid_reload_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Valid Service"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	// Write invalid YAML to trigger reload failure
	invalidCfg := `invalid: yaml: [`
	if err := os.WriteFile(configPath, []byte(invalidCfg), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_MultipleRapidConfigChanges(t *testing.T) {
	oldDelay := ReloadDelay
	ReloadDelay = 500 * time.Millisecond
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "rapid_changes_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Rapid Test"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Trigger multiple rapid writes (debounce should handle this)
	for i := 0; i < 3; i++ {
		newCfg := fmt.Sprintf(`
global:
  default_interval: "50ms"
services:
  - name: "Rapid Test %d"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`, i, MockAlertServerURL)
		if err := os.WriteFile(configPath, []byte(newCfg), 0644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_WatcherEventsClosed(t *testing.T) {
	// Test line 162-163: watcher.Events channel closed
	configFile, err := os.CreateTemp("", "events_closed_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Events Closed Test"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)

	// Start and immediately remove the file to potentially trigger watcher close
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		wd.Start(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	// Delete the config file while watcher is running
	_ = os.Remove(configPath)

	time.Sleep(100 * time.Millisecond)

	cancel()
	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

var MockAlertServerURL string

func TestMain(m *testing.M) {
	// Silence logs during tests
	log.SetOutput(io.Discard)

	// Set a fast refresh rate for tests by default
	originalDelay := ReloadDelay
	ReloadDelay = 10 * time.Millisecond
	StartingWindow = 0

	// Start a global mock server for all tests to use
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	MockAlertServerURL = ts.URL

	code := m.Run()

	ts.Close()
	ReloadDelay = originalDelay
	os.Exit(code)
}

func TestWatchdog_ContextCancelWithTimer(t *testing.T) {
	oldDelay := ReloadDelay
	ReloadDelay = 5 * time.Second
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "timer_cancel_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Timer Cancel Test"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		wd.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Trigger a write event to start the timer
	newCfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Timer Cancel Test Modified"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(newCfgStr, MockAlertServerURL)), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for write event to be detected but cancel before 5s reload
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger timer stop path
	cancel()
	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_TimerTriggeredReload(t *testing.T) {
	// Set short reload delay for testing
	oldDelay := ReloadDelay
	ReloadDelay = 100 * time.Millisecond
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "timer_reload_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Timer Reload Test"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	// Modify config to trigger the reload timer
	newCfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Timer Reload Test Modified"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(newCfgStr, MockAlertServerURL)), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for the timer to trigger reload (100ms delay + buffer)
	time.Sleep(400 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_TimerReloadWithInvalidConfig(t *testing.T) {
	// Set short reload delay for testing
	oldDelay := ReloadDelay
	ReloadDelay = 100 * time.Millisecond
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "timer_invalid_reload_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Timer Invalid Reload Test"
    type: "host"
    interval: "50ms"
    monitor_endpoint:
      success:
        url: "%s"
`
	if _, err := fmt.Fprintf(configFile, cfgStr, MockAlertServerURL); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	// Write invalid YAML to trigger reload failure path
	if err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for the timer to trigger reload (100ms delay + buffer)
	time.Sleep(400 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}
