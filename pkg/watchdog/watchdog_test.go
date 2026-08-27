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
	"sync/atomic"
	"testing"
	"time"

	"probixel/pkg/agent"
	"probixel/pkg/config"
	"probixel/pkg/tunnels"

	"github.com/fsnotify/fsnotify"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type retryingWGDevice struct{}

func (*retryingWGDevice) IpcGet() (string, error) { return "", nil }
func (*retryingWGDevice) IpcSet(string) error     { return nil }
func (*retryingWGDevice) Close()                  {}

func TestWatchdog_Lifecycle(t *testing.T) {
	// Create minimal valid config
	configFile, err := os.CreateTemp("", "lifecycle_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	cfgStr := `
global:
  default_interval: "1s"
services:
  - name: "Lifecycle Test"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      retries: 0
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
    retries: 0
    timeout: "100ms"
    targets: ["127.0.0.1:%d"]
    target_mode: "any"
    udp: {}
    monitor_endpoint:
      retries: 0
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
    retries: 0
    targets: ["127.0.0.1:%d"]
    target_mode: "any"
    udp: {}
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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

func TestWatchdog_RegistersFailedWireguardTunnelForSupervisorRecovery(t *testing.T) {
	originalFactory := newWireguardTunnel
	defer func() { newWireguardTunnel = originalFactory }()

	var attempts atomic.Int32
	recovered := &retryingWGDevice{}
	newWireguardTunnel = func(name string, cfg *config.WireguardConfig) *tunnels.WireguardTunnel {
		tunnel := tunnels.NewWireguardTunnel(name, cfg)
		tunnel.SetDeviceFactory(func() (tunnels.WGDevice, *netstack.Net, error) {
			if attempts.Add(1) == 1 {
				return nil, nil, fmt.Errorf("initial device unavailable")
			}
			return recovered, &netstack.Net{}, nil
		})
		return tunnel
	}

	startingWindow := StartingWindow
	StartingWindow = 0
	defer func() { StartingWindow = startingWindow }()

	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {Type: "wireguard", Wireguard: &config.WireguardConfig{}},
		},
	}
	wd := NewWatchdog("", cfg)
	done := make(chan struct{})
	go func() {
		wd.Start(context.Background())
		close(done)
	}()
	defer func() {
		wd.Stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("watchdog did not stop")
		}
	}()

	deadline := time.After(500 * time.Millisecond)
	for {
		tunnel, registered := wd.tunnelRegistry.Get("wg0")
		if registered {
			if wgTunnel, ok := tunnel.(*tunnels.WireguardTunnel); ok && wgTunnel.Device() == recovered {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatalf("failed tunnel was not registered and recovered after %d attempts", attempts.Load())
		case <-time.After(5 * time.Millisecond):
		}
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, fmt.Appendf(nil, newCfgStr, MockAlertServerURL), 0644); err != nil {
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
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
	for i := range 3 {
		newCfg := fmt.Sprintf(`
global:
  default_interval: "50ms"
services:
  - name: "Rapid Test %d"
    type: "host"
    interval: "50ms"
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, fmt.Appendf(nil, newCfgStr, MockAlertServerURL), 0644); err != nil {
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
    retries: 0
    monitor_endpoint:
      retries: 0
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
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, fmt.Appendf(nil, newCfgStr, MockAlertServerURL), 0644); err != nil {
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
    retries: 0
    monitor_endpoint:
      retries: 0
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

func TestWatchdog_UnknownTunnelType(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Tunnels: map[string]config.TunnelConfig{
			"unknown-tun": {Type: "unknown-type"},
		},
		Services: []config.Service{
			{
				Name:     "Test Service",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
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

func TestWatchdog_TunnelInitFailure(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Tunnels: map[string]config.TunnelConfig{
			"wg-fail": {
				Type: "wireguard",
				Wireguard: &config.WireguardConfig{
					Addresses:  "invalid-addr",
					PrivateKey: "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
					PublicKey:  "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
					Endpoint:   "1.2.3.4:51820",
				},
			},
		},
		Services: []config.Service{
			{
				Name:     "Test Service",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
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

func TestWatchdog_WireguardTunnelWithNilConfig(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Tunnels: map[string]config.TunnelConfig{
			"wg-nil": {Type: "wireguard", Wireguard: nil},
		},
		Services: []config.Service{
			{
				Name:     "Test Service",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
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

func TestWatchdog_SSHTunnelWithNilConfig(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Tunnels: map[string]config.TunnelConfig{
			"ssh-nil": {Type: "ssh", Target: "localhost", SSH: nil},
		},
		Services: []config.Service{
			{
				Name:     "Test Service",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
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

func TestWatchdog_WatcherClose(t *testing.T) {
	// Test the !ok paths when watcher channels close
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Services: []config.Service{
			{
				Name:     "Watcher Close Test",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
	ctx := t.Context()

	// Manually create a watcher and close it to trigger !ok paths
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	wd.wg.Add(1)
	go wd.watchConfigFile(ctx, watcher)

	// Close watcher to trigger channel close -> !ok return
	time.Sleep(50 * time.Millisecond)
	_ = watcher.Close()

	// Wait for goroutine to exit
	done := make(chan struct{})
	go func() {
		wd.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchConfigFile did not return after watcher close")
	}
}

func TestWatchdog_StartingWindowDelay(t *testing.T) {
	// Test the StartingWindow > 0 branch
	oldWindow := StartingWindow
	StartingWindow = 1 * time.Millisecond
	defer func() { StartingWindow = oldWindow }()

	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Services: []config.Service{
			{
				Name:     "Starting Window Test",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
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

func TestWatchLoop_WatcherError(t *testing.T) {
	cfg := &config.Config{}
	wd := NewWatchdog("dummy.yaml", cfg)

	errChan := make(chan error, 1)
	eventChan := make(chan fsnotify.Event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Send an error before starting the loop - it will be picked up immediately
	errChan <- fmt.Errorf("test watcher error")

	done := make(chan struct{})
	go func() {
		wd.watchLoop(ctx, eventChan, errChan, nil)
		close(done)
	}()

	// Wait for the error to be processed
	time.Sleep(50 * time.Millisecond)

	// Cancel to exit the loop
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return")
	}
}

func TestWatchLoop_ErrorsChanClosed(t *testing.T) {
	cfg := &config.Config{}
	wd := NewWatchdog("dummy.yaml", cfg)

	errChan := make(chan error)
	eventChan := make(chan fsnotify.Event)

	done := make(chan struct{})
	go func() {
		wd.watchLoop(context.Background(), eventChan, errChan, nil)
		close(done)
	}()

	// Give the goroutine time to enter the select
	time.Sleep(50 * time.Millisecond)

	// Close the errors channel to trigger the !ok return path
	close(errChan)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return after errors channel closed")
	}
}

func TestWatchdog_ReloadChanFullDefault(t *testing.T) {
	// Test the default case on reloadChan (line 200) when the channel is already full.
	oldDelay := ReloadDelay
	ReloadDelay = 50 * time.Millisecond
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "reload_full_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Reload Full Test"
    type: "host"
    interval: "50ms"
    retries: 0
    monitor_endpoint:
      retries: 0
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

	// Pre-fill the reloadChan so the default case is hit when watchConfigFile tries to send
	wd.reloadChan <- struct{}{}

	// Start watchConfigFile directly (not via Start, to avoid run() draining reloadChan)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Add(configPath); err != nil {
		_ = watcher.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wd.wg.Add(1)
	go wd.watchConfigFile(ctx, watcher)

	// Give watchConfigFile time to enter its select loop
	time.Sleep(50 * time.Millisecond)

	// Modify the file to trigger a write event -> timer starts
	newCfgStr := `
global:
  default_interval: "50ms"
services:
  - name: "Reload Full Test Modified"
    type: "host"
    interval: "50ms"
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, fmt.Appendf(nil, newCfgStr, MockAlertServerURL), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for timer to fire (50ms delay + buffer) and hit the default case
	time.Sleep(200 * time.Millisecond)

	cancel()

	done := make(chan struct{})
	go func() {
		wd.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchConfigFile did not return")
	}
}

func TestWatchdog_RunRespectsContextCancelDuringStartingWindow(t *testing.T) {
	// Test that run() returns when context is cancelled during StartingWindow wait
	oldWindow := StartingWindow
	StartingWindow = 5 * time.Second // long enough that we cancel before it expires
	defer func() { StartingWindow = oldWindow }()

	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Services: []config.Service{
			{
				Name:     "Starting Window Cancel Test",
				Type:     "host",
				Interval: "100ms",
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: MockAlertServerURL},
				},
			},
		},
	}

	wd := NewWatchdog("dummy.yaml", cfg)
	ctx, cancel := context.WithCancel(context.Background())

	wd.wg.Add(1)
	go wd.run(ctx)

	// Give run() time to enter the StartingWindow select
	time.Sleep(50 * time.Millisecond)

	// Cancel context - should cause run() to return before the 5s window
	cancel()

	done := make(chan struct{})
	go func() {
		wd.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - run() exited promptly on context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not return after context cancellation during StartingWindow")
	}
}

func TestWatchLoop_RemoveEvent(t *testing.T) {
	// Test that watchLoop handles fsnotify.Remove events (logs warning, re-adds watch)
	cfg := &config.Config{}
	wd := NewWatchdog("dummy.yaml", cfg)

	eventChan := make(chan fsnotify.Event, 1)
	errChan := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Send a Remove event
	eventChan <- fsnotify.Event{
		Name: "dummy.yaml",
		Op:   fsnotify.Remove,
	}

	done := make(chan struct{})
	go func() {
		wd.watchLoop(ctx, eventChan, errChan, nil) // nil watcher is handled
		close(done)
	}()

	// Give it time to process the event
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return")
	}
}

func TestWatchLoop_CreateEvent(t *testing.T) {
	// Test that watchLoop handles fsnotify.Create events (triggers reload like Write)
	oldDelay := ReloadDelay
	ReloadDelay = 50 * time.Millisecond
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "create_event_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := fmt.Sprintf(`
global:
  default_interval: "50ms"
services:
  - name: "Create Event Test"
    type: "host"
    interval: "50ms"
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`, MockAlertServerURL)
	if _, err := configFile.Write([]byte(cfgStr)); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wd := NewWatchdog(configPath, cfg)

	eventChan := make(chan fsnotify.Event, 1)
	errChan := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		wd.watchLoop(ctx, eventChan, errChan, nil)
		close(done)
	}()

	// Send a Create event - should schedule reload just like Write
	eventChan <- fsnotify.Event{
		Name: configPath,
		Op:   fsnotify.Create,
	}

	// Wait for the timer to fire
	time.Sleep(200 * time.Millisecond)

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return")
	}
}

func TestWatchdog_WatchConfigFilePanicRecovery(t *testing.T) {
	// Test the panic recovery path in watchConfigFile by passing a nil watcher.
	// Accessing watcher.Events on a nil *fsnotify.Watcher will panic,
	// and the recover() defer should handle it gracefully.
	cfg := &config.Config{}
	wd := NewWatchdog("dummy.yaml", cfg)

	ctx := context.Background()
	wd.wg.Add(1)

	// This will panic inside watchConfigFile when it tries to access nil watcher's fields.
	// The defer recover() should catch it.
	go wd.watchConfigFile(ctx, nil)

	done := make(chan struct{})
	go func() {
		wd.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - panic was recovered
	case <-time.After(2 * time.Second):
		t.Fatal("watchConfigFile did not return after panic")
	}
}

func TestWatchdog_OldProbesCleanedUpOnReload(t *testing.T) {
	// Test that old probes implementing Close() are cleaned up on reload
	configFile, err := os.CreateTemp("", "probe_cleanup_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := fmt.Sprintf(`
global:
  default_interval: "100ms"
services:
  - name: "Cleanup Test"
    type: "host"
    interval: "100ms"
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`, MockAlertServerURL)
	if err := os.WriteFile(configPath, []byte(cfgStr), 0644); err != nil {
		t.Fatal(err)
	}

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

	// Let it start and run first iteration
	time.Sleep(100 * time.Millisecond)

	// Trigger a reload - the Close interface on old probes should be called
	select {
	case wd.reloadChan <- struct{}{}:
	default:
	}

	// Let reload complete
	time.Sleep(100 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}

func TestWatchdog_TimerReloadValidWithRestart(t *testing.T) {
	oldDelay := ReloadDelay
	ReloadDelay = 50 * time.Millisecond
	defer func() { ReloadDelay = oldDelay }()

	configFile, err := os.CreateTemp("", "reload_restart_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configPath := configFile.Name()
	defer func() { _ = os.Remove(configPath) }()

	cfgStr := `
global:
  default_interval: "50ms"
  notifier:
    rate_limit: "50ms"
services:
  - name: "Reload Restart Test"
    type: "host"
    interval: "50ms"
    retries: 0
    monitor_endpoint:
      retries: 0
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

	newCfgStr := `
global:
  default_interval: "50ms"
  notifier:
    rate_limit: "100ms"
services:
  - name: "Reload Restart Test Modified"
    type: "host"
    interval: "50ms"
    retries: 0
    monitor_endpoint:
      retries: 0
      success:
        url: "%s"
`
	if err := os.WriteFile(configPath, fmt.Appendf(nil, newCfgStr, MockAlertServerURL), 0644); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	// Wait for timer to fire and reload to complete
	time.Sleep(300 * time.Millisecond)

	wd.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog did not stop")
	}
}
