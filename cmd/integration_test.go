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
	"testing"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// canPing checks whether raw ICMP sockets are available (they aren't in most CI environments).
func canPing() bool {
	p, err := probing.NewPinger("127.0.0.1")
	if err != nil {
		return false
	}
	p.Count = 1
	p.Timeout = 1 * time.Second
	return p.Run() == nil
}

func TestIntegration_AgentLoop(t *testing.T) {
	// Build the agent binary
	agentBin := filepath.Join(os.TempDir(), "probixel-test")
	buildCmd := exec.CommandContext(context.Background(), "go", "build", "-o", agentBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}
	defer func() { _ = os.Remove(agentBin) }()

	// Start a mock server to act as:
	//    The Target (HTTP 200)
	//    The Alert Endpoint (Receives POST)
	pingAvailable := canPing()
	if !pingAvailable {
		t.Log("Ping not available (no raw socket permission), skipping ping assertions")
	}

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

	pingServiceConfig := ""
	if pingAvailable {
		pingServiceConfig = fmt.Sprintf(`
  - name: "Integration Ping Service"
    type: "ping"
    interval: "1s"
    timeout: "500ms"
    retries: 0
    targets: ["127.0.0.1"]
    target_mode: "any"
    ping: {}
    monitor_endpoint:
      retries: 0
      success:
        url: "%s/alert/ping-success?duration={%%%%duration%%%%}"
`, ts.URL)
	}

	configContent := fmt.Sprintf(`
global:
  notifier:
    rate_limit: "0"

services:
  - name: "Reload Test"
    type: "http"
    interval: "1s"
    timeout: "500ms"
    retries: 0
    url: "%[1]s/target"
    http:
      method: "GET"
    monitor_endpoint:
      retries: 0
      success:
        url: "%[1]s/reload-ok"

  - name: "Integration Test Service"
    type: "http"
    interval: "1s"
    timeout: "500ms"
    retries: 0
    url: "%[1]s/target"
    http:
      method: "GET"
    monitor_endpoint:
      retries: 0
      success:
        url: "%[1]s/alert/success?duration={%%duration%%}"
      failure:
        url: "%[1]s/alert/failure?duration={%%duration%%}"

%[3]s
  - name: "Integration UDP Service"
    type: "udp"
    interval: "1s"
    timeout: "500ms"
    retries: 0
    targets: ["127.0.0.1:%[2]d"]
    target_mode: "any"
    udp: {}
    monitor_endpoint:
      retries: 0
      success:
        url: "%[1]s/alert/udp-success?duration={%%duration%%}"
`, ts.URL, udpPort, pingServiceConfig)

	if _, err := configFile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	// Run the Agent with -delay 0 to skip the starting window
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, agentBin, "-config", configFile.Name(), "-delay", "0")
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}

	// Wait for Alerts (fast with -delay 0)
	timeout := time.After(5 * time.Second)
	gotHTTP := false
	gotPing := !pingAvailable // treat as already received when ping is unavailable
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
	tmpDir := t.TempDir()

	// Build the agent binary
	agentBin := filepath.Join(tmpDir, "probixel-health-test")
	buildCmd := exec.CommandContext(context.Background(), "go", "build", "-o", agentBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}

	pidFile := filepath.Join(tmpDir, "probixel-test.pid")

	// Create a valid config (services: [] fails validation)
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(`
services:
  - name: "Health Check Test"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      retries: 0
      success:
        url: "http://localhost/ok"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Verify healthcheck fails when agent is not running
	healthCmd := exec.CommandContext(context.Background(), agentBin, "-health", "-pidfile", pidFile)
	if err := healthCmd.Run(); err == nil {
		t.Error("Expected healthcheck to fail when agent is not running, but it succeeded")
	}

	// Start the agent
	agentCmd := exec.CommandContext(context.Background(), agentBin, "-config", configPath, "-pidfile", pidFile, "-delay", "0")
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}

	// Give it a moment to start and write PID file
	time.Sleep(1 * time.Second)

	// Verify healthcheck succeeds when agent is running
	healthCmd = exec.CommandContext(context.Background(), agentBin, "-health", "-pidfile", pidFile)
	if out, err := healthCmd.CombinedOutput(); err != nil {
		t.Errorf("Expected healthcheck to succeed when agent is running, but it failed: %v\nOutput: %s", err, out)
	}

	// Stop the agent via SIGINT for graceful shutdown (defers run, PID file cleaned up)
	if agentCmd.Process != nil {
		_ = agentCmd.Process.Signal(os.Interrupt)
	}
	_ = agentCmd.Wait()

	// Ensure PID file is removed (graceful shutdown should handle this,
	// but remove explicitly in case the signal was too fast)
	_ = os.Remove(pidFile)

	// Verify healthcheck fails again
	healthCmd = exec.CommandContext(context.Background(), agentBin, "-health", "-pidfile", pidFile)
	if err := healthCmd.Run(); err == nil {
		t.Error("Expected healthcheck to fail after agent stopped, but it succeeded")
	}
}

func TestIntegration_InvalidConfig(t *testing.T) {
	// Build the agent binary
	agentBin := filepath.Join(os.TempDir(), "probixel-invalid-cfg-test")
	buildCmd := exec.CommandContext(context.Background(), "go", "build", "-o", agentBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}
	defer func() { _ = os.Remove(agentBin) }()

	// Create invalid config file
	configPath := filepath.Join(os.TempDir(), "invalid_config.yaml")
	err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configPath) }()

	// Run agent with invalid config - should fail
	pidFile := filepath.Join(os.TempDir(), "probixel-invalid.pid")
	defer func() { _ = os.Remove(pidFile) }()

	cmd := exec.CommandContext(context.Background(), agentBin, "-config", configPath, "-pidfile", pidFile)
	err = cmd.Run()
	if err == nil {
		t.Error("Expected agent to fail with invalid config, but it succeeded")
	}
}

func TestIntegration_MissingConfigFile(t *testing.T) {
	// Build the agent binary
	agentBin := filepath.Join(os.TempDir(), "probixel-missing-cfg-test")
	buildCmd := exec.CommandContext(context.Background(), "go", "build", "-o", agentBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}
	defer func() { _ = os.Remove(agentBin) }()

	// Run agent with missing config - should fail
	cmd := exec.CommandContext(context.Background(), agentBin, "-config", "/nonexistent/path/config.yaml")
	err := cmd.Run()
	if err == nil {
		t.Error("Expected agent to fail with missing config file, but it succeeded")
	}
}

func TestIntegration_GracefulShutdown(t *testing.T) {
	// Build the agent binary
	agentBin := filepath.Join(os.TempDir(), "probixel-shutdown-test")
	buildCmd := exec.CommandContext(context.Background(), "go", "build", "-o", agentBin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build agent: %v\n%s", err, out)
	}
	defer func() { _ = os.Remove(agentBin) }()

	// Create a minimal config
	configPath := filepath.Join(os.TempDir(), "shutdown_config.yaml")
	err := os.WriteFile(configPath, []byte(`
services:
  - name: "Shutdown Test"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      retries: 0
      success:
        url: "http://localhost/ok"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(configPath) }()

	pidFile := filepath.Join(os.TempDir(), "probixel-shutdown.pid")
	defer func() { _ = os.Remove(pidFile) }()

	cmd := exec.CommandContext(context.Background(), agentBin, "-config", configPath, "-pidfile", pidFile, "-delay", "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start agent: %v", err)
	}

	// Give it a moment to start
	time.Sleep(500 * time.Millisecond)

	// Send SIGTERM for graceful shutdown
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}

	// Wait for it to exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		// Graceful shutdown should exit cleanly or with signal
		if err != nil {
			// On some systems, being killed with SIGINT may show as an error
			t.Logf("Agent exited with: %v (this is expected for signal termination)", err)
		}
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		t.Fatal("Agent did not exit within 5 seconds after SIGTERM")
	}
}
