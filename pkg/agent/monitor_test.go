package agent

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/notifier"
	"probixel/pkg/tunnels"
)

func TestMain(m *testing.M) {
	RetryBackoff = 0 // Disable retry backoff in tests for speed
	os.Exit(m.Run())
}

type mockProbe struct {
	name        string
	checkResult monitor.Result
	checkErr    error
	tunnel      tunnels.Tunnel
}

func (m *mockProbe) Name() string { return m.name }
func (m *mockProbe) Check(ctx context.Context, target string) (monitor.Result, error) {
	return m.checkResult, m.checkErr
}
func (m *mockProbe) Close() error { return nil }
func (m *mockProbe) SetTunnel(t tunnels.Tunnel) {
	m.tunnel = t
}
func (m *mockProbe) SetTargetMode(mode string)        {}
func (m *mockProbe) SetTimeout(timeout time.Duration) {}

func TestCheckAndPush(t *testing.T) {
	// Setup dependencies
	ctx := context.Background()
	svcName := "test-service"
	// Initial config needs the service so it can be found
	cfg := &config.Config{
		Services: []config.Service{
			{Name: svcName, Target: "example.com"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	mocksProxy := &tunnels.MockTunnel{
		IsStabilizedResult: true,
	}

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Success: true,
			Message: "OK",
		},
		tunnel: mocksProxy,
	}

	// Just ensure it doesn't panic
	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestRunServiceMonitor_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	svc := config.Service{
		Name:     "monitor-svc",
		Interval: "1s",
	}
	p := &mockProbe{name: "monitor-svc"}
	state := NewConfigState(&config.Config{})
	registry := tunnels.NewRegistry()
	pusher := &notifier.Pusher{}
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go RunServiceMonitor(ctx, svc, p, state, registry, pusher, wg)

	// Let it run for a tiny bit
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("RunServiceMonitor did not stop after context cancellation")
	}
}

func TestCheckAndPush_TunnelUnstable(t *testing.T) {
	ctx := context.Background()
	state := NewConfigState(&config.Config{})
	registry := tunnels.NewRegistry()
	pusher := &notifier.Pusher{}

	// Mock Tunnel NOT stabilized
	unstableTunnel := &tunnels.MockTunnel{
		NameFunc:           func() string { return "t1" },
		IsStabilizedResult: false,
	}
	registry.Register(unstableTunnel)

	p := &mockProbe{
		name:   "service",
		tunnel: unstableTunnel,
		checkResult: monitor.Result{
			Success: false,
			Message: "fail", // should be ignored if unstable (Pending)
		},
	}

	CheckAndPush(ctx, p, "service", state, registry, pusher)
	// Verify no panic and logic flow. Functional verification is harder without checking logs or pusher output
	// But in unit test, assume dependencies work.
}

func TestCheckAndPush_WithURL(t *testing.T) {
	ctx := context.Background()
	svcName := "url-service"
	cfg := &config.Config{
		Services: []config.Service{
			{Name: svcName, URL: "http://example.com"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Success: true,
			Message: "OK",
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestCheckAndPush_WithTargets(t *testing.T) {
	ctx := context.Background()
	svcName := "targets-service"
	cfg := &config.Config{
		Services: []config.Service{
			{Name: svcName, Targets: []string{"host1", "host2"}},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Success: true,
			Message: "OK",
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestCheckAndPush_ServiceNotFound(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{
		Services: []config.Service{
			{Name: "other-service"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{name: "missing-service"}

	// Should not panic when service is not found
	CheckAndPush(ctx, p, "missing-service", state, registry, pusher)
}

func TestCheckAndPush_WithTunnelSuccess(t *testing.T) {
	ctx := context.Background()
	svcName := "tunnel-service"
	tunnelName := "my-tunnel"

	mockT := &tunnels.MockTunnel{
		NameFunc: func() string { return tunnelName },
	}
	registry := tunnels.NewRegistry()
	registry.Register(mockT)

	cfg := &config.Config{
		Services: []config.Service{
			{Name: svcName, Target: "target", Tunnel: tunnelName},
		},
	}
	state := NewConfigState(cfg)
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Success: true,
			Message: "OK",
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestCheckAndPush_ProbeError(t *testing.T) {
	ctx := context.Background()
	svcName := "error-service"
	cfg := &config.Config{
		Services: []config.Service{
			{Name: svcName, Target: "target"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name:     svcName,
		checkErr: context.DeadlineExceeded,
	}

	// Should handle probe error without panic
	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestCheckAndPush_PendingResult(t *testing.T) {
	ctx := context.Background()
	svcName := "pending-service"
	cfg := &config.Config{
		Services: []config.Service{
			{Name: svcName, Target: "target"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Pending: true,
			Message: "Waiting",
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestRunServiceMonitor_InvalidInterval(t *testing.T) {
	ctx := t.Context()

	svc := config.Service{
		Name:     "invalid-interval-svc",
		Interval: "invalid",
	}
	p := &mockProbe{name: "invalid-interval-svc"}
	state := NewConfigState(&config.Config{})
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go RunServiceMonitor(ctx, svc, p, state, registry, pusher, wg)

	// Should return quickly due to invalid interval
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success - returned due to invalid interval
	case <-time.After(1 * time.Second):
		t.Fatal("RunServiceMonitor did not return after invalid interval")
	}
}

func TestRunServiceMonitor_UsesGlobalDefaultInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	svc := config.Service{
		Name:     "global-interval-svc",
		Interval: "", // Empty, should use global
	}
	cfg := &config.Config{
		Global: config.GlobalConfig{
			DefaultInterval: "100ms",
		},
		Services: []config.Service{svc},
	}
	p := &mockProbe{name: "global-interval-svc"}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go RunServiceMonitor(ctx, svc, p, state, registry, pusher, wg)

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("RunServiceMonitor did not stop after context cancellation")
	}
}
func TestCheckAndPush_ProbeRetries(t *testing.T) {
	ctx := context.Background()
	svcName := "retry-service"
	cfg := &config.Config{
		Global: config.GlobalConfig{
			Monitor: config.MonitorConfig{
				Retries: new(3),
			},
		},
		Services: []config.Service{
			{Name: svcName, Target: "target", Type: "http"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	attempts := 0
	p := &mockProbe{
		name: svcName,
		// Custom Check implementation for this test
	}

	// Override Check for this specific test to track attempts
	checkFunc := func(ctx context.Context, target string) (monitor.Result, error) {
		attempts++
		if attempts < 3 {
			return monitor.Result{Success: false, Message: "failed"}, nil
		}
		return monitor.Result{Success: true, Message: "OK"}, nil
	}

	// Override Check for this specific test to track attempts
	sp := &statusMockProbe{
		mockProbe: *p,
		checkFunc: checkFunc,
	}

	CheckAndPush(ctx, sp, svcName, state, registry, pusher)

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

type statusMockProbe struct {
	mockProbe
	checkFunc func(ctx context.Context, target string) (monitor.Result, error)
}

func (s *statusMockProbe) Check(ctx context.Context, target string) (monitor.Result, error) {
	return s.checkFunc(ctx, target)
}

func TestCheckAndPush_ProbeRetries_Exemptions(t *testing.T) {
	ctx := context.Background()
	svcName := "exempt-service"
	cfg := &config.Config{
		Global: config.GlobalConfig{
			Monitor: config.MonitorConfig{
				Retries: new(3),
			},
		},
		Services: []config.Service{
			{Name: svcName, Target: "target", Type: "host"}, // host is exempt
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	attempts := 0
	p := &statusMockProbe{
		checkFunc: func(ctx context.Context, target string) (monitor.Result, error) {
			attempts++
			return monitor.Result{Success: false, Message: "failed"}, nil
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)

	if attempts != 1 {
		t.Errorf("Expected 1 attempt for exempt host service, got %d", attempts)
	}
}

func TestCheckAndPush_ServiceLevelRetries(t *testing.T) {
	ctx := context.Background()
	svcName := "svc-retries"
	svcRetries := 2
	cfg := &config.Config{
		Global: config.GlobalConfig{
			Monitor: config.MonitorConfig{
				Retries: new(5), // global retries
			},
		},
		Services: []config.Service{
			{Name: svcName, Target: "target", Type: "http", Retries: &svcRetries},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	attempts := 0
	p := &statusMockProbe{
		checkFunc: func(ctx context.Context, target string) (monitor.Result, error) {
			attempts++
			return monitor.Result{Success: false, Message: "failed"}, nil
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)

	// Service-level retries (2) should override global (5): 1 initial + 2 retries = 3 attempts
	if attempts != 3 {
		t.Errorf("Expected 3 attempts (1+2 retries), got %d", attempts)
	}
}

func TestCheckAndPush_ProbeRetriesWithError(t *testing.T) {
	ctx := context.Background()
	svcName := "error-retry-svc"
	cfg := &config.Config{
		Global: config.GlobalConfig{
			Monitor: config.MonitorConfig{
				Retries: new(2),
			},
		},
		Services: []config.Service{
			{Name: svcName, Target: "target", Type: "http"},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	attempts := 0
	p := &statusMockProbe{
		checkFunc: func(ctx context.Context, target string) (monitor.Result, error) {
			attempts++
			return monitor.Result{}, fmt.Errorf("internal probe error")
		},
	}

	CheckAndPush(ctx, p, svcName, state, registry, pusher)

	// Should retry on error: 1 initial + 2 retries = 3 attempts
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

// panicProbe is a probe that panics on Check, for testing panic recovery
type panicProbe struct {
	mockProbe
}

func (p *panicProbe) Check(_ context.Context, _ string) (monitor.Result, error) {
	panic("test panic from probe")
}

func TestRunServiceMonitor_RecoverFromPanic(t *testing.T) {
	ctx := t.Context()

	svc := config.Service{
		Name:     "panic-service",
		Interval: "100ms",
	}
	cfg := &config.Config{
		Services: []config.Service{svc},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()
	wg := &sync.WaitGroup{}

	p := &panicProbe{}

	wg.Add(1)
	go RunServiceMonitor(ctx, svc, p, state, registry, pusher, wg)

	// Wait for the goroutine to complete (it should recover from the panic and return)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - panic was recovered, goroutine exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("RunServiceMonitor did not return after panic")
	}
}

func TestCheckAndPush_PusherError(t *testing.T) {
	ctx := context.Background()
	svcName := "pusher-error-svc"
	cfg := &config.Config{
		Services: []config.Service{
			{
				Name:   svcName,
				Target: "target",
				Type:   "http",
				MonitorEndpoint: config.MonitorEndpointConfig{
					// Point to a non-existent endpoint to trigger push error
					Success: config.EndpointConfig{
						URL: "http://127.0.0.1:1/nonexistent",
					},
					Retries: new(0),
				},
			},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Success: true,
			Message: "OK",
		},
	}

	// Should not panic when pusher returns an error
	CheckAndPush(ctx, p, svcName, state, registry, pusher)
}

func TestCheckAndPush_CancelDuringRetryBackoff(t *testing.T) {
	// Test the ctx.Done() path during retry backoff (monitor.go lines 119-120)
	oldBackoff := RetryBackoff
	RetryBackoff = 5 * time.Second // Long backoff so we can cancel during it
	defer func() { RetryBackoff = oldBackoff }()

	retries := 3
	svcName := "cancel-during-retry"
	cfg := &config.Config{
		Global: config.GlobalConfig{DefaultInterval: "100ms"},
		Services: []config.Service{
			{
				Name:     svcName,
				Type:     "http",
				Interval: "100ms",
				Retries:  &retries,
				Targets:  []string{"http://localhost:1"},
				MonitorEndpoint: config.MonitorEndpointConfig{
					Success: config.EndpointConfig{URL: "http://localhost:1/push"},
				},
			},
		},
	}
	state := NewConfigState(cfg)
	registry := tunnels.NewRegistry()
	pusher := notifier.NewPusher()

	p := &mockProbe{
		name: svcName,
		checkResult: monitor.Result{
			Success: false,
			Message: "fail",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		CheckAndPush(ctx, p, svcName, state, registry, pusher)
		close(done)
	}()

	// Give it time to enter the retry backoff
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger ctx.Done() during backoff
	cancel()

	select {
	case <-done:
		// Success - returned promptly after cancel
	case <-time.After(2 * time.Second):
		t.Fatal("CheckAndPush did not return after context cancellation during retry backoff")
	}
}
