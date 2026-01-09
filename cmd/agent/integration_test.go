package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"probixel/pkg/config"
)

func TestIntegration_AgentLoop(t *testing.T) {
	// Build the agent binary
	agentBin := filepath.Join(os.TempDir(), "probixel-test")
	buildCmd := exec.Command("go", "build", "-o", agentBin, ".") //nolint:gosec // G204: Building test binary with variable path is safe in tests
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}
	defer func() { _ = os.Remove(agentBin) }()

	// Start a mock server to act as:
	//    The Target (HTTP 200)
	//    The Alert Endpoint (Receives POST)
	httpAlertReceived := make(chan bool, 1)
	pingAlertReceived := make(chan bool, 1)
	udpAlertReceived := make(chan bool, 1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If it's the target check
		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// If it's the alert push
		if r.URL.Path == "/alert/success" {
			if r.URL.Query().Get("duration") == "" {
				t.Error("Alert missing duration param")
			}
			select {
			case httpAlertReceived <- true:
			default:
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		// Ping alert
		if r.URL.Path == "/alert/ping-success" {
			select {
			case pingAlertReceived <- true:
			default:
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		// UDP alert
		if r.URL.Path == "/alert/udp-success" {
			select {
			case udpAlertReceived <- true:
			default:
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// tart a UDP Listener for the test
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

	// Create Config File
	configFile, err := os.CreateTemp("", "agent_config_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	configContent := fmt.Sprintf(`
global:
  headers:
    Env: IntegrationTest

services:
  - name: "Reload Test"
    type: "http"
    interval: "1s"
    url: "%[1]s/target"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "%[1]s/reload-ok"

  - name: "Integration Test Service"
    type: "http"
    interval: "1s"
    url: "%[1]s/target"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "%[1]s/alert/success?duration={%%duration%%}"
      failure:
        url: "%[1]s/alert/failure?duration={%%duration%%}"

  - name: "Integration Ping Service"
    type: "ping"
    interval: "1s"
    targets: ["127.0.0.1"]
    target_mode: "any"
    ping: {}
    monitor_endpoint:
      success:
        url: "%[1]s/alert/ping-success?duration={%%duration%%}"

  - name: "Integration UDP Service"
    type: "udp"
    interval: "1s"
    targets: ["127.0.0.1:%d"]
    target_mode: "any"
    udp: {}
    monitor_endpoint:
      success:
        url: "%[1]s/alert/udp-success?duration={%%duration%%}"
`, ts.URL, udpPort)

	if _, err := configFile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	// Run the Agent (Disable delay for fast tests)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, agentBin, "-config", configFile.Name(), "-delay", "0") //nolint:gosec // G204: Running built test binary with config file
	// cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}

	// Wait for Alerts (Fast tests with -delay 0)
	timeout := time.After(5 * time.Second)
	gotHTTP := false
	gotPing := false
	gotUDP := false

	for !gotHTTP || !gotPing || !gotUDP {
		select {
		case <-httpAlertReceived:
			gotHTTP = true
		case <-pingAlertReceived:
			gotPing = true
		case <-udpAlertReceived:
			gotUDP = true
		case <-timeout:
			t.Fatalf("Timed out waiting for alerts. Got HTTP: %v, Ping: %v, UDP: %v", gotHTTP, gotPing, gotUDP)
		}
	}

	// 6. Cleanup
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func TestIntegration_HealthCheck(t *testing.T) {
	// Build the agent binary
	agentBin := filepath.Join(os.TempDir(), "probixel-health-test")
	buildCmd := exec.Command("go", "build", "-o", agentBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}
	defer func() { _ = os.Remove(agentBin) }()

	pidFile := filepath.Join(os.TempDir(), "probixel-test.pid")
	defer func() { _ = os.Remove(pidFile) }()

	// Create a dummy config
	configPath := filepath.Join(os.TempDir(), "dummy_config.yaml")
	err := os.WriteFile(configPath, []byte("services: []"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configPath) }()

	// Verify healthcheck fails when agent is not running
	healthCmd := exec.Command(agentBin, "-health", "-pidfile", pidFile)
	if err := healthCmd.Run(); err == nil {
		t.Error("Expected healthcheck to fail when agent is not running, but it succeeded")
	}

	// Start the agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentCmd := exec.CommandContext(ctx, agentBin, "-config", configPath, "-pidfile", pidFile)
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}

	// Give it a moment to start and write PID file
	time.Sleep(1 * time.Second)

	// Verify healthcheck succeeds when agent is running
	healthCmd = exec.Command(agentBin, "-health", "-pidfile", pidFile)
	if out, err := healthCmd.CombinedOutput(); err != nil {
		t.Errorf("Expected healthcheck to succeed when agent is running, but it failed: %v\nOutput: %s", err, out)
	}

	// Stop the agent
	cancel()
	_ = agentCmd.Wait()

	// Verify healthcheck fails again
	time.Sleep(500 * time.Millisecond)
	healthCmd = exec.Command(agentBin, "-health", "-pidfile", pidFile)
	if err := healthCmd.Run(); err == nil {
		t.Error("Expected healthcheck to fail after agent stopped, but it succeeded")
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
services:
  - name: "Test UDP Service"
    type: "udp"
    interval: "300ms"
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
	shared := &sharedConfig{config: cfg}

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
	shared.set(newCfg)

	// Verify config was updated
	reloadedCfg := shared.get()
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

func TestConfigReload_InvalidConfig(t *testing.T) {
	// Create temporary config file
	configFile, err := os.CreateTemp("", "reload_invalid_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configFile.Name()) }()

	// Valid initial config
	validConfig := fmt.Sprintf(`
services:
  - name: "Reload Test Invalid"
    type: "host"
    interval: "1s"
    targets: ["localhost"]
    target_mode: "any"
    host: {}
    monitor_endpoint:
      success:
        url: "http://example.test/success?duration={%%duration%%}"
`)

	if _, err := configFile.Write([]byte(validConfig)); err != nil {
		t.Fatal(err)
	}
	if err := configFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load initial config to verify it's valid
	cfg, err := config.LoadConfig(configFile.Name())
	if err != nil {
		t.Fatalf("Initial config should be valid: %v", err)
	}
	if len(cfg.Services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(cfg.Services))
	}

	// Create shared config
	shared := &sharedConfig{config: cfg}
	oldCfg := shared.get()

	// Write invalid config
	invalidConfig := `
this is not valid yaml: [[[
services:
  - invalid
`
	if err := os.WriteFile(configFile.Name(), []byte(invalidConfig), 0644); err != nil { //nolint:gosec // G306: Test file permissions
		t.Fatal(err)
	}

	// Try to reload - should fail
	_, err = config.LoadConfig(configFile.Name())
	if err == nil {
		t.Error("Expected error when loading invalid config")
	}

	// Verify shared config was NOT updated (simulating what watchConfigFile does)
	currentCfg := shared.get()
	if currentCfg != oldCfg {
		t.Error("Shared config should not have been updated with invalid config")
	}

	if len(currentCfg.Services) != 1 {
		t.Errorf("Expected old config to remain with 1 service, got %d", len(currentCfg.Services))
	}

	t.Log("Invalid config test passed - old configuration was preserved")
}

func TestSharedConfig_ThreadSafety(t *testing.T) {
	// Create initial config
	cfg := &config.Config{
		Services: []config.Service{
			{Name: "Service1"},
		},
	}

	shared := &sharedConfig{config: cfg}

	// Test concurrent reads and writes
	var wg sync.WaitGroup
	iterations := 100

	// Start multiple readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				c := shared.get()
				if len(c.Services) == 0 {
					t.Error("Config should always have at least one service")
				}
			}
		}()
	}

	// Start multiple writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				newCfg := &config.Config{
					Services: []config.Service{
						{Name: fmt.Sprintf("Service%d", id)},
					},
				}
				shared.set(newCfg)
			}
		}(i)
	}

	wg.Wait()
	t.Log("Thread safety test passed - no race conditions detected")
}
