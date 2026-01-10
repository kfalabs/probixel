package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/notifier"
	"probixel/pkg/tunnels"
)

// MockProbe for testing
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
