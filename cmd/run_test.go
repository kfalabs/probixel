package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"probixel/pkg/watchdog"
)

func TestRun_InvalidConfigPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pidFile := filepath.Join(t.TempDir(), "test.pid")
	err := run(ctx, "/nonexistent/config.yaml", pidFile, 0)
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !contains(err.Error(), "failed to load config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_InvalidPidFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := run(ctx, "config.yaml", "/nonexistent/dir/test.pid", 0)
	if err == nil {
		t.Fatal("expected error for bad pid file path")
	}
	if !contains(err.Error(), "failed to write PID file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_ValidConfig_CancelContext(t *testing.T) {
	// Ensure no leftover StartingWindow from other tests
	oldWindow := watchdog.StartingWindow
	defer func() { watchdog.StartingWindow = oldWindow }()

	// Create a mock alert server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a valid config file
	configContent := fmt.Sprintf(`
services:
  - name: "Unit Test Service"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      retries: 0
      success:
        url: "%s/ok"
`, ts.URL)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	pidFile := filepath.Join(t.TempDir(), "test.pid")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, configPath, pidFile, 0)
	}()

	// Let it run briefly, then cancel
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after context cancellation")
	}

	// PID file should have been cleaned up
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("expected PID file to be removed after run returns")
	}
}

func TestRun_InvalidYAMLConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(configPath, []byte("invalid: yaml: ["), 0644); err != nil {
		t.Fatal(err)
	}

	pidFile := filepath.Join(t.TempDir(), "test.pid")
	ctx := context.Background()

	err := run(ctx, configPath, pidFile, 0)
	if err == nil {
		t.Fatal("expected error for invalid YAML config")
	}
}

func TestRun_SignalShutdown(t *testing.T) {
	oldWindow := watchdog.StartingWindow
	defer func() { watchdog.StartingWindow = oldWindow }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	configContent := fmt.Sprintf(`
services:
  - name: "Signal Test Service"
    type: "host"
    interval: "1s"
    monitor_endpoint:
      retries: 0
      success:
        url: "%s/ok"
`, ts.URL)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	pidFile := filepath.Join(t.TempDir(), "test.pid")

	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, configPath, pidFile, 0)
	}()

	// Let the agent start, then send SIGINT to trigger signal handler
	time.Sleep(200 * time.Millisecond)
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after SIGINT")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
