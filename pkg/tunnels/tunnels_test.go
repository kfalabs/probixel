package tunnels

import (
	"context"
	"net"
	"testing"
	"time"
)

type mockTunnel struct {
	name string
	tp   string
}

func (m *mockTunnel) Name() string      { return m.name }
func (m *mockTunnel) Type() string      { return m.tp }
func (m *mockTunnel) Initialize() error { return nil }
func (m *mockTunnel) Stop()             {}
func (m *mockTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}
func (m *mockTunnel) LastInitTime() time.Time { return time.Time{} }
func (m *mockTunnel) ReportFailure()          {}
func (m *mockTunnel) ReportSuccess()          {}
func (m *mockTunnel) IsStabilized() bool      { return true }

func TestRegistry_StopAll(t *testing.T) {
	r := NewRegistry()
	stopped := false
	mock := &MockTunnel{
		NameFunc: func() string { return "t1" },
		StopFunc: func() { stopped = true },
	}
	_ = r.Register(mock)

	r.StopAll()
	if !stopped {
		t.Error("expected Stop to be called")
	}
}

func TestMockTunnel_AllMethods(t *testing.T) {
	// Test default behaviors (no funcs set)
	m := &MockTunnel{}

	if m.Name() != "mock" {
		t.Errorf("expected default name 'mock', got %s", m.Name())
	}
	if m.Type() != "mock" {
		t.Errorf("expected default type 'mock', got %s", m.Type())
	}
	if err := m.Initialize(); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	m.Stop() // should not panic

	conn, err := m.DialContext(context.TODO(), "tcp", "localhost:80")
	if conn != nil || err != nil {
		t.Errorf("expected nil conn and err, got %v, %v", conn, err)
	}

	if !m.LastInitTime().IsZero() {
		t.Error("expected zero time")
	}

	m.ReportFailure() // should not panic
	m.ReportSuccess() // should not panic

	if m.IsStabilized() {
		t.Error("expected false when IsStabilizedResult is not set")
	}
}

func TestMockTunnel_WithFuncs(t *testing.T) {
	nameCalled := false
	typeCalled := false
	initCalled := false
	stopCalled := false
	dialCalled := false
	lastInitCalled := false
	failureCalled := false

	m := &MockTunnel{
		NameFunc:       func() string { nameCalled = true; return "custom" },
		TypeFunc:       func() string { typeCalled = true; return "custom-type" },
		InitializeFunc: func() error { initCalled = true; return nil },
		StopFunc:       func() { stopCalled = true },
		DialContextFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCalled = true
			return nil, nil
		},
		LastInitTimeFunc:   func() time.Time { lastInitCalled = true; return time.Now() },
		ReportFailureFunc:  func() { failureCalled = true },
		IsStabilizedResult: true,
	}

	if m.Name() != "custom" || !nameCalled {
		t.Error("NameFunc not called correctly")
	}
	if m.Type() != "custom-type" || !typeCalled {
		t.Error("TypeFunc not called correctly")
	}
	if err := m.Initialize(); err != nil || !initCalled {
		t.Error("InitializeFunc not called correctly")
	}
	m.Stop()
	if !stopCalled {
		t.Error("StopFunc not called")
	}
	_, _ = m.DialContext(context.Background(), "tcp", "localhost:80")
	if !dialCalled {
		t.Error("DialContextFunc not called")
	}
	_ = m.LastInitTime()
	if !lastInitCalled {
		t.Error("LastInitTimeFunc not called")
	}
	m.ReportFailure()
	if !failureCalled {
		t.Error("ReportFailureFunc not called")
	}
	if !m.IsStabilized() {
		t.Error("expected IsStabilized to return true")
	}
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()
	t1 := &mockTunnel{name: "t1", tp: "ssh"}
	t2 := &mockTunnel{name: "t2", tp: "wireguard"}

	if err := reg.Register(t1); err != nil {
		t.Fatalf("failed to register t1: %v", err)
	}

	if err := reg.Register(t1); err == nil {
		t.Error("expected error when registering duplicate tunnel")
	}

	if err := reg.Register(t2); err != nil {
		t.Fatalf("failed to register t2: %v", err)
	}

	got, ok := reg.Get("t1")
	if !ok || got != t1 {
		t.Errorf("expected t1, got %v", got)
	}

	got, ok = reg.Get("t2")
	if !ok || got != t2 {
		t.Errorf("expected t2, got %v", got)
	}

	_, ok = reg.Get("nonexistent")
	if ok {
		t.Error("expected false for nonexistent tunnel")
	}

	reg.StopAll()
	_, ok = reg.Get("t1")
	if ok {
		t.Error("expected false after StopAll")
	}
}
